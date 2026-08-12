"""GovernanceService — business logic for all six governance endpoints.

This service composes GovernanceRepository, AuditRepository (for appending
the retention-policy change audit event) and the classification registry.
No SQL lives here — all DB access is delegated to repositories.

The service validates retention_days before writing to ensure the 90-day
policy maximum is never exceeded, and emits exactly one audit_event per
PUT /retention-policy call containing before/after values.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from ..authz.guard import ActorContext
from ..governance.classification import ClassificationEntry, get_classification_inventory
from ..governance.cursor import CursorError, decode_cursor, encode_cursor
from ..governance.models import (
    AuditEventItem,
    AuditEventListResponse,
    ClassificationEntryResponse,
    ClassificationInventoryResponse,
    ExportHistoryItem,
    ExportHistoryListResponse,
    PurgeReceiptItem,
    PurgeReceiptListResponse,
    RetentionPolicyResponse,
    RetentionPolicyUpdateRequest,
)
from ..persistence.models.audit_event import AuditEvent
from ..persistence.models.purge_receipt import PurgeReceipt
from ..persistence.models.retention_policy import RetentionPolicy
from ..persistence.repositories.audit import AuditRepository
from ..persistence.repositories.governance import GovernanceRepository

_MAX_RETENTION_DAYS = 90


class GovernanceValidationError(ValueError):
    """Raised when a governance write request fails validation."""


class GovernanceService:
    """Orchestrates governance queries and the retention-policy write path."""

    def __init__(
        self,
        governance_repo: GovernanceRepository,
        audit_repo: AuditRepository,
    ) -> None:
        self._gov = governance_repo
        self._audit = audit_repo

    # ------------------------------------------------------------------
    # Classification inventory
    # ------------------------------------------------------------------

    def get_classification_inventory(self) -> ClassificationInventoryResponse:
        entries = get_classification_inventory()
        return ClassificationInventoryResponse(
            entities=[
                ClassificationEntryResponse(
                    name=e.name,
                    tier=e.tier,
                    retention=e.retention,
                    encryption=e.encryption,
                    masking_rule=e.masking_rule,
                    access_rule=e.access_rule,
                )
                for e in entries
            ]
        )

    # ------------------------------------------------------------------
    # Audit events
    # ------------------------------------------------------------------

    def list_audit_events(
        self,
        *,
        actor: ActorContext,
        limit: int = 50,
        cursor: str | None = None,
        actor_id: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> AuditEventListResponse:
        cursor_occurred_at = None
        cursor_id = None
        if cursor:
            cursor_occurred_at, cursor_id = decode_cursor(cursor)

        rows = self._gov.list_audit_events(
            limit=limit,
            cursor_occurred_at=cursor_occurred_at,
            cursor_id=cursor_id,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            from_dt=from_dt,
            to_dt=to_dt,
        )

        has_more = len(rows) > limit
        page = rows[:limit]

        next_cursor = None
        if has_more and page:
            last = page[-1]
            next_cursor = encode_cursor(last.occurred_at, last.id)

        workspace_id_str = str(actor.workspace_id)
        items = [
            AuditEventItem(
                id=row.id,
                occurred_at=row.occurred_at,
                actor_id=row.actor_id,
                actor_display=row.actor_id,
                actor_persona=row.actor_persona,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                workspace_id=workspace_id_str,
                change_detail=row.change_detail or {},
                correlation_id=row.correlation_id,
            )
            for row in page
        ]
        return AuditEventListResponse(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
        )

    # ------------------------------------------------------------------
    # Purge receipts
    # ------------------------------------------------------------------

    def list_purge_receipts(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> PurgeReceiptListResponse:
        cursor_occurred_at = None
        cursor_id = None
        if cursor:
            cursor_occurred_at, cursor_id = decode_cursor(cursor)

        rows = self._gov.list_purge_receipts(
            limit=limit,
            cursor_occurred_at=cursor_occurred_at,
            cursor_id=cursor_id,
        )

        has_more = len(rows) > limit
        page = rows[:limit]

        next_cursor = None
        if has_more and page:
            last = page[-1]
            next_cursor = encode_cursor(last.executed_at, last.id)

        items = [
            PurgeReceiptItem(
                id=row.id,
                batch_id=row.batch_id,
                executed_at=row.executed_at,
                entity_counts=row.deleted_counts or {},
                verification_digest=row.verification_digest,
                status=_infer_purge_status(row),
                error_detail=_infer_error_detail(row),
            )
            for row in page
        ]
        return PurgeReceiptListResponse(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
        )

    # ------------------------------------------------------------------
    # Retention policy
    # ------------------------------------------------------------------

    def get_retention_policy(self) -> RetentionPolicyResponse:
        policy = self._gov.get_retention_policy()
        last_run = self._gov.get_last_purge_run()
        sla_breaches = self._gov.count_purge_sla_breaches()

        if policy is None:
            return RetentionPolicyResponse(
                retention_days=_MAX_RETENTION_DAYS,
                next_run_at=None,
                last_run_at=last_run.executed_at if last_run else None,
                last_run_status=_infer_purge_status(last_run) if last_run else None,
                purge_sla_breaches=sla_breaches,
                updated_by="system",
                updated_at=datetime.now(timezone.utc),
            )

        return RetentionPolicyResponse(
            retention_days=policy.retention_days,
            next_run_at=None,
            last_run_at=last_run.executed_at if last_run else None,
            last_run_status=_infer_purge_status(last_run) if last_run else None,
            purge_sla_breaches=sla_breaches,
            updated_by=str(policy.updated_by),
            updated_at=policy.updated_at,
        )

    def update_retention_policy(
        self,
        request: RetentionPolicyUpdateRequest,
        actor: ActorContext,
    ) -> RetentionPolicyResponse:
        """Update the retention policy and emit one audit_event.

        Validation:
        - retention_days must be 1–90 (enforced by Pydantic model).
        - Cannot exceed _MAX_RETENTION_DAYS (double-checked here for safety).

        Audit event contains before/after values so the change is fully audited.
        """
        if request.retention_days > _MAX_RETENTION_DAYS:
            raise GovernanceValidationError(
                f"retention_days={request.retention_days} exceeds the maximum "
                f"allowed value of {_MAX_RETENTION_DAYS} days for Confidential entities."
            )

        existing = self._gov.get_retention_policy()
        before_days = existing.retention_days if existing else _MAX_RETENTION_DAYS

        now = datetime.now(timezone.utc)
        policy = self._gov.upsert_retention_policy(
            retention_days=request.retention_days,
            updated_by=actor.workspace_id,
            updated_at=now,
        )

        # Emit audit event — exactly one per policy change.
        audit_event = AuditEvent(
            actor_id=actor.actor_id,
            actor_persona=actor.persona,
            occurred_at=now,
            resource_type="retention_policy",
            resource_id="1",
            action="retention_policy.update",
            change_detail={
                "before": {"retention_days": before_days},
                "after": {"retention_days": request.retention_days},
                "updated_by": actor.actor_id,
            },
        )
        self._audit.append(audit_event)

        return RetentionPolicyResponse(
            retention_days=policy.retention_days,
            next_run_at=None,
            last_run_at=None,
            last_run_status=None,
            purge_sla_breaches=self._gov.count_purge_sla_breaches(),
            updated_by=actor.actor_id,
            updated_at=policy.updated_at,
        )

    # ------------------------------------------------------------------
    # Export history
    # ------------------------------------------------------------------

    def list_export_history(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> ExportHistoryListResponse:
        cursor_occurred_at = None
        cursor_id = None
        if cursor:
            cursor_occurred_at, cursor_id = decode_cursor(cursor)

        rows = self._gov.list_export_history(
            limit=limit,
            cursor_occurred_at=cursor_occurred_at,
            cursor_id=cursor_id,
        )

        has_more = len(rows) > limit
        page = rows[:limit]

        next_cursor = None
        if has_more and page:
            last = page[-1]
            next_cursor = encode_cursor(last.occurred_at, last.id)

        items = [
            ExportHistoryItem(
                id=row.id,
                occurred_at=row.occurred_at,
                actor_id=row.actor_id,
                actor_display=row.actor_id,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                format=row.change_detail.get("format") if row.change_detail else None,
            )
            for row in page
        ]
        return ExportHistoryListResponse(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_purge_status(row: PurgeReceipt) -> str:
    if row.verification_digest == "FAILED":
        return "failed"
    return "completed"


def _infer_error_detail(row: PurgeReceipt) -> str | None:
    if row.verification_digest == "FAILED":
        cd = row.deleted_counts or {}
        return cd.get("error", "Purge batch failed; see system logs for details.")
    return None
