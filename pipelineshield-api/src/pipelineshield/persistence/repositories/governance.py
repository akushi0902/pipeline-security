"""GovernanceRepository — cursor-paginated governance queries.

All queries are read-only (SELECT) except update_retention_policy which
performs a single-row UPSERT via SQLAlchemy merge.

Cursor format: (occurred_at, id) — see governance.cursor for encode/decode.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..models.audit_event import AuditEvent
from ..models.purge_receipt import PurgeReceipt
from ..models.retention_policy import RetentionPolicy

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


class GovernanceRepository:
    """Read-oriented repository for governance console queries.

    All SQL is parameterized.  No UPDATE or DELETE on audit_event is possible
    through this repository; only RetentionPolicy supports write operations.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Audit events
    # ------------------------------------------------------------------

    def list_audit_events(
        self,
        *,
        limit: int = _DEFAULT_LIMIT,
        cursor_occurred_at: datetime | None = None,
        cursor_id: uuid.UUID | None = None,
        actor_id: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[AuditEvent]:
        """Return audit events in descending occurred_at, id order.

        Fetches limit+1 rows to determine has_more.
        """
        limit = max(1, min(limit, _MAX_LIMIT))
        stmt = select(AuditEvent)

        if cursor_occurred_at is not None and cursor_id is not None:
            # Keyset pagination: rows strictly before the cursor boundary.
            stmt = stmt.where(
                (AuditEvent.occurred_at < cursor_occurred_at)
                | (
                    (AuditEvent.occurred_at == cursor_occurred_at)
                    & (AuditEvent.id < cursor_id)
                )
            )

        if actor_id is not None:
            stmt = stmt.where(AuditEvent.actor_id == actor_id)
        if action is not None:
            stmt = stmt.where(AuditEvent.action == action)
        if resource_type is not None:
            stmt = stmt.where(AuditEvent.resource_type == resource_type)
        if from_dt is not None:
            stmt = stmt.where(AuditEvent.occurred_at >= from_dt)
        if to_dt is not None:
            stmt = stmt.where(AuditEvent.occurred_at <= to_dt)

        stmt = (
            stmt.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .limit(limit + 1)
        )
        return list(self._session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------
    # Purge receipts
    # ------------------------------------------------------------------

    def list_purge_receipts(
        self,
        *,
        limit: int = _DEFAULT_LIMIT,
        cursor_occurred_at: datetime | None = None,
        cursor_id: uuid.UUID | None = None,
    ) -> list[PurgeReceipt]:
        """Return purge receipts in descending executed_at order.

        Fetches limit+1 rows to determine has_more.
        """
        limit = max(1, min(limit, _MAX_LIMIT))
        stmt = select(PurgeReceipt)

        if cursor_occurred_at is not None and cursor_id is not None:
            stmt = stmt.where(
                (PurgeReceipt.executed_at < cursor_occurred_at)
                | (
                    (PurgeReceipt.executed_at == cursor_occurred_at)
                    & (PurgeReceipt.id < cursor_id)
                )
            )

        stmt = (
            stmt.order_by(PurgeReceipt.executed_at.desc(), PurgeReceipt.id.desc())
            .limit(limit + 1)
        )
        return list(self._session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------
    # Export history (reads audit_event with action = 'export.create')
    # ------------------------------------------------------------------

    def list_export_history(
        self,
        *,
        limit: int = _DEFAULT_LIMIT,
        cursor_occurred_at: datetime | None = None,
        cursor_id: uuid.UUID | None = None,
    ) -> list[AuditEvent]:
        """Return export audit events in descending occurred_at order.

        Export events are audit_event rows where action = 'export.create'.
        This avoids a parallel export table and maintains one source of truth.
        """
        limit = max(1, min(limit, _MAX_LIMIT))
        stmt = select(AuditEvent).where(AuditEvent.action == "export.create")

        if cursor_occurred_at is not None and cursor_id is not None:
            stmt = stmt.where(
                (AuditEvent.occurred_at < cursor_occurred_at)
                | (
                    (AuditEvent.occurred_at == cursor_occurred_at)
                    & (AuditEvent.id < cursor_id)
                )
            )

        stmt = (
            stmt.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .limit(limit + 1)
        )
        return list(self._session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------
    # Retention policy
    # ------------------------------------------------------------------

    def get_retention_policy(self) -> RetentionPolicy | None:
        """Return the current retention policy row, or None if not yet set."""
        stmt = select(RetentionPolicy).where(RetentionPolicy.id == 1)
        return self._session.execute(stmt).scalar_one_or_none()

    def upsert_retention_policy(
        self,
        retention_days: int,
        updated_by: uuid.UUID,
        updated_at: datetime,
    ) -> RetentionPolicy:
        """Create or update the retention policy row (id=1).

        This is the only write method in GovernanceRepository.  The caller
        is responsible for emitting the accompanying audit_event BEFORE
        committing so the before/after values are recorded atomically.
        """
        existing = self.get_retention_policy()
        if existing is None:
            policy = RetentionPolicy(
                id=1,
                retention_days=retention_days,
                updated_by=updated_by,
                updated_at=updated_at,
            )
            self._session.add(policy)
        else:
            existing.retention_days = retention_days  # type: ignore[assignment]
            existing.updated_by = updated_by  # type: ignore[assignment]
            existing.updated_at = updated_at  # type: ignore[assignment]
            policy = existing
        self._session.flush()
        return policy

    # ------------------------------------------------------------------
    # Purge SLA metrics (derived from purge_receipt and audit_event)
    # ------------------------------------------------------------------

    def count_purge_sla_breaches(self) -> int:
        """Return the number of purge receipts with status='failed'."""
        stmt = text(
            "SELECT COUNT(*) FROM purge_receipt "
            "WHERE deleted_counts::text LIKE '%\"status\": \"failed\"%' "
            "OR verification_digest = 'FAILED'"
        )
        try:
            result = self._session.execute(stmt).scalar()
            return int(result or 0)
        except Exception:
            return 0

    def get_last_purge_run(self) -> PurgeReceipt | None:
        """Return the most recent purge receipt."""
        stmt = (
            select(PurgeReceipt)
            .order_by(PurgeReceipt.executed_at.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalar_one_or_none()
