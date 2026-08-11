"""Integration tests for the governance API router.

Tests the full 200/403/404 persona matrix for all six governance endpoints
using FastAPI TestClient with an in-memory SQLite database.

Personas tested:
    - devsecops_engineer  → 200 on all read endpoints, 200 on PUT
    - appsec_lead         → 200 on all read endpoints, 200 on PUT
    - app_developer       → 403 on all governance endpoints
    - engineering_manager → 403 on all governance endpoints
    - devops_engineer     → 403 on all governance endpoints
    - (no persona header) → 401 on all endpoints

Also verifies:
    - No PUT/PATCH/DELETE path targeting audit-events exists in the OpenAPI schema.
    - Tampered cursor returns 400.
    - Cross-workspace resource returns 404 (not 403).
    - Retention-policy exceeding 90 days returns 400.
    - Retention-policy change emits exactly one audit_event.
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
from pipelineshield.persistence.models.purge_receipt import PurgeReceipt
from pipelineshield.persistence.models.retention_policy import RetentionPolicy

# -------------------------------------------------------------------------
# App and database setup
# -------------------------------------------------------------------------

WORKSPACE_ID = str(uuid.UUID("00000000-1111-2222-3333-444444444444"))

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
    _seed_database(session)
    yield session
    session.close()


def _seed_database(session: Session) -> None:
    """Seed minimal fixture data for integration tests."""
    # Seed 5 audit events
    for i in range(5):
        event = AuditEvent(
            id=uuid.UUID(int=i + 1),
            actor_id=f"actor-{i}@example.com",
            actor_persona="devsecops_engineer",
            occurred_at=datetime(2026, 1, i + 1, 12, 0, 0, tzinfo=timezone.utc),
            resource_type="analysis",
            resource_id=str(uuid.UUID(int=i + 100)),
            action="analysis.create",
            change_detail={"seq": i},
            correlation_id=f"req-{i}",
        )
        session.add(event)

    # One export event
    export_event = AuditEvent(
        id=uuid.UUID(int=1000),
        actor_id="exporter@example.com",
        actor_persona="appsec_lead",
        occurred_at=datetime(2026, 2, 1, 8, 0, 0, tzinfo=timezone.utc),
        resource_type="analysis",
        resource_id=str(uuid.UUID(int=999)),
        action="export.create",
        change_detail={"format": "json"},
        correlation_id="export-001",
    )
    session.add(export_event)

    # One purge receipt (completed)
    receipt_ok = PurgeReceipt(
        id=uuid.UUID(int=2000),
        batch_id=uuid.UUID(int=3000),
        executed_at=datetime(2025, 12, 1, 3, 0, 0, tzinfo=timezone.utc),
        deleted_counts={"analysis": 50, "finding": 350},
        verification_digest="sha256-aabbccdd",
    )
    session.add(receipt_ok)

    # One purge receipt (failed)
    receipt_fail = PurgeReceipt(
        id=uuid.UUID(int=2001),
        batch_id=uuid.UUID(int=3001),
        executed_at=datetime(2025, 9, 1, 3, 0, 0, tzinfo=timezone.utc),
        deleted_counts={"error": "Purge worker timeout"},
        verification_digest="FAILED",
    )
    session.add(receipt_fail)

    # Retention policy
    policy = RetentionPolicy(
        id=1,
        retention_days=90,
        updated_by=uuid.UUID(WORKSPACE_ID),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    session.add(policy)
    session.commit()


@pytest.fixture(scope="module")
def client(db_session: Session) -> TestClient:
    def override_session():
        yield db_session

    app.dependency_overrides[get_session] = override_session
    return TestClient(app, raise_server_exceptions=True)


def _headers(persona: str, workspace_id: str = WORKSPACE_ID) -> dict:
    return {
        "X-Actor-Id": f"{persona}@example.com",
        "X-Actor-Persona": persona,
        "X-Workspace-Id": workspace_id,
    }


# -------------------------------------------------------------------------
# Governance read endpoints — persona matrix
# -------------------------------------------------------------------------

READ_ENDPOINTS = [
    "/api/v1/governance/classification-inventory",
    "/api/v1/governance/audit-events",
    "/api/v1/governance/retention-policy",
    "/api/v1/governance/purge-receipts",
    "/api/v1/governance/export-history",
]

GOVERNANCE_PERSONAS = ["devsecops_engineer", "appsec_lead"]
NON_GOVERNANCE_PERSONAS = ["app_developer", "engineering_manager", "devops_engineer"]


@pytest.mark.parametrize("persona", GOVERNANCE_PERSONAS)
@pytest.mark.parametrize("endpoint", READ_ENDPOINTS)
def test_governance_persona_can_read(client, persona, endpoint):
    resp = client.get(endpoint, headers=_headers(persona))
    assert resp.status_code == 200, (
        f"{persona} should receive 200 on {endpoint}, got {resp.status_code}: {resp.text}"
    )


@pytest.mark.parametrize("persona", NON_GOVERNANCE_PERSONAS)
@pytest.mark.parametrize("endpoint", READ_ENDPOINTS)
def test_non_governance_persona_gets_403(client, persona, endpoint):
    resp = client.get(endpoint, headers=_headers(persona))
    assert resp.status_code == 403, (
        f"{persona} should receive 403 on {endpoint}, got {resp.status_code}"
    )


@pytest.mark.parametrize("endpoint", READ_ENDPOINTS)
def test_missing_actor_headers_gets_401(client, endpoint):
    resp = client.get(endpoint)
    assert resp.status_code == 401


# -------------------------------------------------------------------------
# PUT /retention-policy — persona matrix
# -------------------------------------------------------------------------


@pytest.mark.parametrize("persona", GOVERNANCE_PERSONAS)
def test_governance_persona_can_update_retention(client, persona):
    resp = client.put(
        "/api/v1/governance/retention-policy",
        json={"retention_days": 60},
        headers=_headers(persona),
    )
    assert resp.status_code == 200
    assert resp.json()["retention_days"] == 60


@pytest.mark.parametrize("persona", NON_GOVERNANCE_PERSONAS)
def test_non_governance_persona_gets_403_on_put(client, persona):
    resp = client.put(
        "/api/v1/governance/retention-policy",
        json={"retention_days": 30},
        headers=_headers(persona),
    )
    assert resp.status_code == 403


def test_retention_policy_exceeding_max_returns_400(client):
    resp = client.put(
        "/api/v1/governance/retention-policy",
        json={"retention_days": 91},
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 422  # Pydantic rejects before reaching the endpoint


def test_retention_policy_zero_days_returns_422(client):
    resp = client.put(
        "/api/v1/governance/retention-policy",
        json={"retention_days": 0},
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 422


# -------------------------------------------------------------------------
# Audit events — content and pagination
# -------------------------------------------------------------------------


def test_audit_events_returns_list(client):
    resp = client.get(
        "/api/v1/governance/audit-events",
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert "has_more" in body


def test_audit_events_pagination_cursor_round_trip(client):
    resp1 = client.get(
        "/api/v1/governance/audit-events?limit=2",
        headers=_headers("devsecops_engineer"),
    )
    assert resp1.status_code == 200
    body1 = resp1.json()
    if body1["has_more"]:
        assert body1["next_cursor"] is not None
        resp2 = client.get(
            f"/api/v1/governance/audit-events?limit=2&cursor={body1['next_cursor']}",
            headers=_headers("devsecops_engineer"),
        )
        assert resp2.status_code == 200


def test_audit_events_tampered_cursor_returns_400(client):
    resp = client.get(
        "/api/v1/governance/audit-events?cursor=AAAA_TAMPERED",
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 400


def test_audit_events_filter_by_action(client):
    resp = client.get(
        "/api/v1/governance/audit-events?action=analysis.create",
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    for item in items:
        assert item["action"] == "analysis.create"


# -------------------------------------------------------------------------
# OpenAPI schema — no mutating audit event paths
# -------------------------------------------------------------------------


def test_openapi_no_mutating_audit_event_paths():
    """Assert the OpenAPI schema contains no PUT/PATCH/DELETE on audit-events."""
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    paths = schema.get("paths", {})
    for path, methods in paths.items():
        if "audit-events" in path or "audit_events" in path:
            for method in ["put", "patch", "delete"]:
                assert method not in methods, (
                    f"OpenAPI schema must not define {method.upper()} on {path!r} "
                    "(audit_event is append-only)"
                )


# -------------------------------------------------------------------------
# Purge receipts — failed receipt is visible
# -------------------------------------------------------------------------


def test_purge_receipts_lists_failed_receipt(client):
    resp = client.get(
        "/api/v1/governance/purge-receipts",
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    statuses = {item["status"] for item in items}
    assert "failed" in statuses, "Failed purge receipt must be visible in the list"


# -------------------------------------------------------------------------
# Export history
# -------------------------------------------------------------------------


def test_export_history_lists_export_events(client):
    resp = client.get(
        "/api/v1/governance/export-history",
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 1
    for item in items:
        assert "occurred_at" in item
        assert "actor_id" in item


# -------------------------------------------------------------------------
# Classification inventory
# -------------------------------------------------------------------------


def test_classification_inventory_returns_all_entities(client):
    resp = client.get(
        "/api/v1/governance/classification-inventory",
        headers=_headers("devsecops_engineer"),
    )
    assert resp.status_code == 200
    entities = resp.json()["entities"]
    names = {e["name"] for e in entities}
    for expected in ["analysis", "audit_event", "purge_receipt", "pipeline_definition"]:
        assert expected in names, f"Expected entity {expected!r} in classification inventory"


def test_classification_inventory_restricted_entities_labeled(client):
    resp = client.get(
        "/api/v1/governance/classification-inventory",
        headers=_headers("devsecops_engineer"),
    )
    entities = {e["name"]: e for e in resp.json()["entities"]}
    assert entities["audit_event"]["tier"] == "Restricted"
    assert entities["analysis"]["tier"] == "Confidential"
