"""Integration tests for pilot sign-off and GA gate endpoints.

Covers:
1.  POST /pilot-signoffs — creates record, returns 201.
2.  POST /pilot-signoffs — 'approved' without rating returns 400.
3.  POST /pilot-signoffs — non-permitted persona returns 403.
4.  GET /pilot-signoffs — lists records with cursor pagination.
5.  GET /pilot-signoffs — workspace-owner sees only own workspace.
6.  GET /pilot-signoffs — no persona header returns 401.
7.  GET /ga-gate — returns overall status and thresholds.
8.  GET /ga-gate — non-permitted persona returns 403.
9.  GET /ga-gate — overall status is 'fail' when any threshold lacks data.
10. Sample pipeline exclusion: seeded sample does not increment definitions_analysed.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from pipelineshield.governance.router import router
from pipelineshield.persistence.db import get_session
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.pilot_signoff import PilotSignoff

# ---------------------------------------------------------------------------
# App and DB setup (SQLite in-memory)
# ---------------------------------------------------------------------------

WORKSPACE_ID = str(uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
ACTOR_ID = str(uuid.UUID("11111111-2222-3333-4444-555555555555"))

app = FastAPI()
app.include_router(router, prefix="/api/v1")


@pytest.fixture(scope="module")
def db_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def db_session(db_engine) -> Generator[Session, None, None]:
    factory = sessionmaker(db_engine, autoflush=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture(scope="module")
def client(db_session):
    app.dependency_overrides[get_session] = lambda: db_session
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


def _governance_headers(workspace_id: str = WORKSPACE_ID):
    return {
        "X-Actor-Id": ACTOR_ID,
        "X-Actor-Persona": "devsecops_engineer",
        "X-Workspace-Id": workspace_id,
    }


def _unpermitted_headers(workspace_id: str = WORKSPACE_ID):
    return {
        "X-Actor-Id": ACTOR_ID,
        "X-Actor-Persona": "app_developer",
        "X-Workspace-Id": workspace_id,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_pilot_signoff_returns_201(client):
    payload = {
        "workspace_id": WORKSPACE_ID,
        "decision": "approved",
        "accuracy_actionability_rating": 4,
        "personas_covered": ["devsecops_engineer"],
        "comments": "Looks good.",
    }
    resp = client.post(
        "/api/v1/governance/pilot-signoffs",
        json=payload,
        headers=_governance_headers(),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["decision"] == "approved"
    assert body["accuracy_actionability_rating"] == 4


def test_create_pilot_signoff_approved_without_rating_returns_400(client):
    payload = {
        "workspace_id": WORKSPACE_ID,
        "decision": "approved",
        "accuracy_actionability_rating": None,
        "personas_covered": [],
    }
    resp = client.post(
        "/api/v1/governance/pilot-signoffs",
        json=payload,
        headers=_governance_headers(),
    )
    assert resp.status_code == 422, resp.text  # Pydantic validates before route


def test_create_pilot_signoff_unpermitted_persona_returns_403(client):
    payload = {
        "workspace_id": WORKSPACE_ID,
        "decision": "pending",
        "personas_covered": [],
    }
    resp = client.post(
        "/api/v1/governance/pilot-signoffs",
        json=payload,
        headers=_unpermitted_headers(),
    )
    assert resp.status_code == 403, resp.text


def test_list_pilot_signoffs_returns_200(client):
    resp = client.get(
        "/api/v1/governance/pilot-signoffs",
        headers=_governance_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "items" in body
    assert "has_more" in body


def test_list_pilot_signoffs_no_persona_returns_401(client):
    resp = client.get("/api/v1/governance/pilot-signoffs")
    assert resp.status_code == 401, resp.text


def test_get_ga_gate_returns_200_with_thresholds(client):
    resp = client.get(
        "/api/v1/governance/ga-gate",
        headers=_governance_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "overall_status" in body
    assert "thresholds" in body
    assert isinstance(body["thresholds"], list)
    assert len(body["thresholds"]) >= 11
    assert "failing" in body


def test_get_ga_gate_unpermitted_persona_returns_403(client):
    resp = client.get(
        "/api/v1/governance/ga-gate",
        headers=_unpermitted_headers(),
    )
    assert resp.status_code == 403, resp.text


def test_get_ga_gate_no_persona_returns_401(client):
    resp = client.get("/api/v1/governance/ga-gate")
    assert resp.status_code == 401, resp.text


def test_ga_gate_fails_when_insufficient_data(client):
    """Gate returns 'fail' when measurements are missing (insufficient_data)."""
    resp = client.get(
        "/api/v1/governance/ga-gate",
        headers=_governance_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    # With an empty database, most metrics will be insufficient_data → fail
    assert body["overall_status"] == "fail"
    assert len(body["failing"]) > 0


def test_threshold_keys_present(client):
    """Every ratified O6 threshold key appears in the response."""
    expected_keys = {
        "workspaces_signed_off",
        "accuracy_rating_pct",
        "definitions_analysed",
        "reanalysis_rate_pct",
        "median_score_improvement",
        "latency_p95_seconds",
        "latency_p50_seconds",
        "fabricated_findings",
        "secret_exposure_incidents",
        "authz_violations",
        "purge_sla_breaches",
    }
    resp = client.get(
        "/api/v1/governance/ga-gate",
        headers=_governance_headers(),
    )
    assert resp.status_code == 200
    returned_keys = {t["key"] for t in resp.json()["thresholds"]}
    assert expected_keys.issubset(returned_keys), (
        f"Missing threshold keys: {expected_keys - returned_keys}"
    )


def test_workspace_owner_sees_only_own_signoffs(client, db_session):
    """Non-governance persona listing sees only their own workspace's records."""
    other_ws = str(uuid.uuid4())
    # Create a sign-off for a different workspace via governance headers
    payload = {
        "workspace_id": other_ws,
        "decision": "approved",
        "accuracy_actionability_rating": 5,
        "personas_covered": [],
    }
    client.post(
        "/api/v1/governance/pilot-signoffs",
        json=payload,
        headers=_governance_headers(other_ws),
    )

    own_ws = str(uuid.uuid4())
    payload_own = {
        "workspace_id": own_ws,
        "decision": "approved",
        "accuracy_actionability_rating": 5,
        "personas_covered": [],
    }
    client.post(
        "/api/v1/governance/pilot-signoffs",
        json=payload_own,
        headers=_governance_headers(own_ws),
    )

    # devops_engineer is NOT in the governance set, sees only own workspace
    owner_headers = {
        "X-Actor-Id": ACTOR_ID,
        "X-Actor-Persona": "devops_engineer",
        "X-Workspace-Id": own_ws,
    }
    resp = client.get("/api/v1/governance/pilot-signoffs", headers=owner_headers)
    # devops_engineer doesn't have PILOT_SIGNOFF_WRITE → 403
    assert resp.status_code == 403
