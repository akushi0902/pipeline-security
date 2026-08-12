"""Unit tests for GovernanceService methods.

Uses in-memory mock repositories to test service logic without a database.
Tests:
1. get_classification_inventory returns all entities.
2. list_audit_events applies cursor pagination correctly.
3. list_audit_events returns correct has_more flag.
4. update_retention_policy emits one audit event.
5. update_retention_policy rejects values > 90.
6. list_purge_receipts returns failed receipt status.
7. list_export_history returns only export.create events.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

try:
    from pydantic import ValidationError

    from pipelineshield.authz.guard import ActorContext
    from pipelineshield.governance.models import RetentionPolicyUpdateRequest
    from pipelineshield.governance.service import GovernanceService, GovernanceValidationError
    from pipelineshield.persistence.models.audit_event import AuditEvent
    from pipelineshield.persistence.models.purge_receipt import PurgeReceipt
    from pipelineshield.persistence.models.retention_policy import RetentionPolicy

    _DEPS_AVAILABLE = True
except ImportError:
    _DEPS_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _DEPS_AVAILABLE,
    reason="pydantic/fastapi not installed — skipping service unit tests",
)

WORKSPACE_ID = uuid.UUID("00000000-1111-2222-3333-444444444444")
_ACTOR = ActorContext(
    actor_id="gov@example.com",
    persona="devsecops_engineer",
    workspace_id=WORKSPACE_ID,
) if _DEPS_AVAILABLE else None


def _make_event(
    i: int,
    action: str = "analysis.create",
    resource_type: str = "analysis",
) -> "AuditEvent":
    return AuditEvent(
        id=uuid.UUID(int=i),
        actor_id=f"actor-{i}@example.com",
        actor_persona="devsecops_engineer",
        occurred_at=datetime(2025, 1, i + 1, tzinfo=timezone.utc),
        resource_type=resource_type,
        resource_id=str(uuid.UUID(int=i + 1000)),
        action=action,
        change_detail={"seq": i},
    )


def _make_service(
    audit_events=None,
    purge_receipts=None,
    retention_policy=None,
    export_events=None,
):
    gov_repo = MagicMock()
    audit_repo = MagicMock()

    gov_repo.list_audit_events.return_value = audit_events or []
    gov_repo.list_purge_receipts.return_value = purge_receipts or []
    gov_repo.list_export_history.return_value = export_events or []
    gov_repo.get_retention_policy.return_value = retention_policy
    gov_repo.get_last_purge_run.return_value = None
    gov_repo.count_purge_sla_breaches.return_value = 0

    def _upsert(retention_days, updated_by, updated_at):
        pol = MagicMock()
        pol.retention_days = retention_days
        pol.updated_by = updated_by
        pol.updated_at = updated_at
        return pol

    gov_repo.upsert_retention_policy.side_effect = _upsert
    audit_repo.append.return_value = MagicMock()

    return GovernanceService(gov_repo, audit_repo), gov_repo, audit_repo


# ------------------------------------------------------------------
# Classification inventory
# ------------------------------------------------------------------


def test_classification_inventory_returns_entities():
    service, _, _ = _make_service()
    result = service.get_classification_inventory()
    assert len(result.entities) > 0
    names = {e.name for e in result.entities}
    assert "audit_event" in names
    assert "analysis" in names


# ------------------------------------------------------------------
# Audit events
# ------------------------------------------------------------------


def test_list_audit_events_no_more(monkeypatch):
    events = [_make_event(i) for i in range(3)]
    service, gov_repo, _ = _make_service(audit_events=events)

    result = service.list_audit_events(actor=_ACTOR, limit=50)

    assert len(result.items) == 3
    assert result.has_more is False
    assert result.next_cursor is None


def test_list_audit_events_has_more(monkeypatch):
    # Service fetches limit+1 from repo; 6 events with limit=5 → has_more=True
    events = [_make_event(i) for i in range(6)]
    service, _, _ = _make_service(audit_events=events)

    result = service.list_audit_events(actor=_ACTOR, limit=5)

    assert len(result.items) == 5
    assert result.has_more is True
    assert result.next_cursor is not None


# ------------------------------------------------------------------
# Retention policy update
# ------------------------------------------------------------------


def test_update_retention_policy_emits_audit_event():
    service, _, audit_repo = _make_service()
    req = RetentionPolicyUpdateRequest(retention_days=45)

    result = service.update_retention_policy(req, _ACTOR)

    assert result.retention_days == 45
    audit_repo.append.assert_called_once()
    audit_event = audit_repo.append.call_args[0][0]
    assert audit_event.action == "retention_policy.update"
    assert audit_event.change_detail["after"]["retention_days"] == 45


def test_update_retention_policy_records_before_value():
    existing_policy = MagicMock()
    existing_policy.retention_days = 90
    service, _, audit_repo = _make_service(retention_policy=existing_policy)

    req = RetentionPolicyUpdateRequest(retention_days=30)
    service.update_retention_policy(req, _ACTOR)

    audit_event = audit_repo.append.call_args[0][0]
    assert audit_event.change_detail["before"]["retention_days"] == 90
    assert audit_event.change_detail["after"]["retention_days"] == 30


def test_update_retention_policy_rejects_over_90():
    service, _, _ = _make_service()
    with pytest.raises(ValidationError):
        RetentionPolicyUpdateRequest(retention_days=91)


# ------------------------------------------------------------------
# Purge receipts
# ------------------------------------------------------------------


def test_list_purge_receipts_failed_status():
    receipt = PurgeReceipt(
        id=uuid.UUID(int=1),
        batch_id=uuid.UUID(int=2),
        executed_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
        deleted_counts={"error": "timeout"},
        verification_digest="FAILED",
    )
    service, _, _ = _make_service(purge_receipts=[receipt])

    result = service.list_purge_receipts(limit=10)

    assert len(result.items) == 1
    assert result.items[0].status == "failed"
    assert result.items[0].error_detail is not None


# ------------------------------------------------------------------
# Export history
# ------------------------------------------------------------------


def test_list_export_history():
    export_event = _make_event(1, action="export.create", resource_type="analysis")
    export_event.change_detail = {"format": "json"}
    service, _, _ = _make_service(export_events=[export_event])

    result = service.list_export_history(limit=10)

    assert len(result.items) == 1
    assert result.items[0].format == "json"
