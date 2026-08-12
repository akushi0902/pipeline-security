"""Unit tests for PilotSignoffService — sign-off validation and persona scoping.

Tests (all pass without database or network, using in-memory stubs):
1.  Valid 'approved' sign-off with rating creates record and audit event.
2.  'rejected' sign-off with rating creates record.
3.  'pending' sign-off without rating creates record.
4.  'approved' without rating raises PilotSignoffValidationError.
5.  'rejected' without rating raises PilotSignoffValidationError.
6.  Non-governance persona signing off another workspace raises error.
7.  Governance persona signing off any workspace succeeds.
8.  list_signoffs: governance sees all, workspace-owner sees only their own.
9.  Audit event is emitted exactly once per successful creation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from pipelineshield.authz.guard import ActorContext
from pipelineshield.governance.models import PilotSignoffCreateRequest
from pipelineshield.governance.pilot_signoff_service import (
    PilotSignoffService,
    PilotSignoffValidationError,
)
from pipelineshield.persistence.models.pilot_signoff import PilotSignoff


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _StubSignoffRepo:
    def __init__(self):
        self.records: list[PilotSignoff] = []

    def create(self, record: PilotSignoff) -> PilotSignoff:
        self.records.append(record)
        return record

    def list_all(self, *, limit=50, cursor_recorded_at=None, cursor_id=None):
        return self.records[:limit]

    def list_by_workspace(self, workspace_id, *, limit=50, cursor_recorded_at=None, cursor_id=None):
        return [r for r in self.records if r.workspace_id == workspace_id][:limit]

    def count_workspaces_with_decision(self, decision):
        return sum(1 for r in self.records if r.decision == decision)

    def count_distinct_pilot_workspaces(self):
        return len({r.workspace_id for r in self.records})

    def average_accuracy_rating_pct(self):
        rated = [r.accuracy_actionability_rating for r in self.records
                 if r.accuracy_actionability_rating is not None]
        if not rated:
            return None
        return sum(1 for x in rated if x >= 4) * 100 // len(rated)


class _StubAuditRepo:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


class _StubMetricsRepo:
    def count_definitions_analysed(self): return 0
    def reanalysis_rate_pct(self): return None
    def median_score_improvement(self): return None
    def latency_percentiles_seconds(self): return None, None
    def count_authz_violations(self): return 0
    def count_purge_sla_breaches(self): return 0


def _make_actor(
    persona: str = "devsecops_engineer",
    workspace_id: uuid.UUID | None = None,
    actor_id: str | None = None,
) -> ActorContext:
    return ActorContext(
        actor_id=actor_id or str(uuid.uuid4()),
        persona=persona,
        workspace_id=workspace_id or uuid.uuid4(),
    )


def _make_service():
    signoff_repo = _StubSignoffRepo()
    audit_repo = _StubAuditRepo()
    metrics_repo = _StubMetricsRepo()
    service = PilotSignoffService(
        signoff_repo=signoff_repo,
        audit_repo=audit_repo,
        metrics_repo=metrics_repo,
    )
    return service, signoff_repo, audit_repo


WS_ID = uuid.uuid4()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_approved_with_rating_creates_record():
    service, repo, _ = _make_service()
    actor = _make_actor(workspace_id=WS_ID)
    req = PilotSignoffCreateRequest(
        workspace_id=WS_ID,
        decision="approved",
        accuracy_actionability_rating=5,
        personas_covered=["devsecops_engineer"],
    )
    result = service.create_signoff(req, actor)
    assert result.decision == "approved"
    assert result.accuracy_actionability_rating == 5
    assert len(repo.records) == 1


def test_rejected_with_rating_creates_record():
    service, repo, _ = _make_service()
    actor = _make_actor(workspace_id=WS_ID)
    req = PilotSignoffCreateRequest(
        workspace_id=WS_ID,
        decision="rejected",
        accuracy_actionability_rating=2,
        personas_covered=["appsec_lead"],
    )
    result = service.create_signoff(req, actor)
    assert result.decision == "rejected"
    assert len(repo.records) == 1


def test_pending_without_rating_creates_record():
    service, repo, _ = _make_service()
    actor = _make_actor(workspace_id=WS_ID)
    req = PilotSignoffCreateRequest(
        workspace_id=WS_ID,
        decision="pending",
        personas_covered=[],
    )
    result = service.create_signoff(req, actor)
    assert result.decision == "pending"
    assert result.accuracy_actionability_rating is None
    assert len(repo.records) == 1


def test_approved_without_rating_raises_validation_error():
    with pytest.raises(ValueError, match="accuracy_actionability_rating"):
        PilotSignoffCreateRequest(
            workspace_id=WS_ID,
            decision="approved",
            accuracy_actionability_rating=None,
            personas_covered=[],
        )


def test_rejected_without_rating_raises_validation_error():
    with pytest.raises(ValueError, match="accuracy_actionability_rating"):
        PilotSignoffCreateRequest(
            workspace_id=WS_ID,
            decision="rejected",
            accuracy_actionability_rating=None,
            personas_covered=[],
        )


def test_non_governance_signing_other_workspace_raises():
    service, _, _ = _make_service()
    own_ws = uuid.uuid4()
    other_ws = uuid.uuid4()
    actor = _make_actor(persona="devops_engineer", workspace_id=own_ws)
    req = PilotSignoffCreateRequest(
        workspace_id=other_ws,
        decision="approved",
        accuracy_actionability_rating=4,
        personas_covered=[],
    )
    with pytest.raises(PilotSignoffValidationError, match="own workspace"):
        service.create_signoff(req, actor)


def test_governance_persona_can_sign_any_workspace():
    service, repo, _ = _make_service()
    own_ws = uuid.uuid4()
    other_ws = uuid.uuid4()
    actor = _make_actor(persona="devsecops_engineer", workspace_id=own_ws)
    req = PilotSignoffCreateRequest(
        workspace_id=other_ws,
        decision="approved",
        accuracy_actionability_rating=4,
        personas_covered=["devsecops_engineer"],
    )
    result = service.create_signoff(req, actor)
    assert result.workspace_id == other_ws
    assert len(repo.records) == 1


def test_list_signoffs_governance_sees_all():
    service, repo, _ = _make_service()
    ws_a = uuid.uuid4()
    ws_b = uuid.uuid4()

    for ws in [ws_a, ws_b]:
        actor = _make_actor(persona="devsecops_engineer", workspace_id=ws)
        service.create_signoff(
            PilotSignoffCreateRequest(
                workspace_id=ws,
                decision="approved",
                accuracy_actionability_rating=5,
                personas_covered=[],
            ),
            actor,
        )

    gov_actor = _make_actor(persona="devsecops_engineer", workspace_id=uuid.uuid4())
    result = service.list_signoffs(gov_actor)
    assert len(result.items) == 2


def test_list_signoffs_workspace_owner_sees_only_own():
    service, repo, _ = _make_service()
    ws_a = uuid.uuid4()
    ws_b = uuid.uuid4()

    for ws in [ws_a, ws_b]:
        actor = _make_actor(persona="devsecops_engineer", workspace_id=ws)
        service.create_signoff(
            PilotSignoffCreateRequest(
                workspace_id=ws,
                decision="approved",
                accuracy_actionability_rating=5,
                personas_covered=[],
            ),
            actor,
        )

    # devops_engineer (not in governance set) sees only their workspace
    owner_actor = ActorContext(
        actor_id=str(uuid.uuid4()),
        persona="devops_engineer",
        workspace_id=ws_a,
    )
    result = service.list_signoffs(owner_actor)
    assert all(item.workspace_id == ws_a for item in result.items)


def test_audit_event_emitted_exactly_once():
    service, _, audit_repo = _make_service()
    actor = _make_actor(workspace_id=WS_ID)
    service.create_signoff(
        PilotSignoffCreateRequest(
            workspace_id=WS_ID,
            decision="approved",
            accuracy_actionability_rating=4,
            personas_covered=[],
        ),
        actor,
    )
    assert len(audit_repo.events) == 1
    assert audit_repo.events[0].action == "pilot_signoff.create"
