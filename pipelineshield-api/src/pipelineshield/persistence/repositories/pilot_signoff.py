"""PilotSignoffRepository — cursor-paginated reads and append-only writes.

No UPDATE or DELETE methods exist.  Corrections are new records.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.pilot_signoff import PilotSignoff

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


class PilotSignoffRepository:
    """Append-only repository for pilot sign-off records."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, record: PilotSignoff) -> PilotSignoff:
        """Persist a new sign-off record and flush (no commit)."""
        self._session.add(record)
        self._session.flush()
        return record

    def list_all(
        self,
        *,
        limit: int = _DEFAULT_LIMIT,
        cursor_recorded_at: datetime | None = None,
        cursor_id: uuid.UUID | None = None,
    ) -> list[PilotSignoff]:
        """Governance view: list all sign-offs across all workspaces.

        Fetches limit+1 rows to allow the caller to compute has_more.
        """
        limit = max(1, min(limit, _MAX_LIMIT))
        stmt = select(PilotSignoff)

        if cursor_recorded_at is not None and cursor_id is not None:
            stmt = stmt.where(
                (PilotSignoff.recorded_at < cursor_recorded_at)
                | (
                    (PilotSignoff.recorded_at == cursor_recorded_at)
                    & (PilotSignoff.id < cursor_id)
                )
            )

        stmt = (
            stmt.order_by(PilotSignoff.recorded_at.desc(), PilotSignoff.id.desc())
            .limit(limit + 1)
        )
        return list(self._session.execute(stmt).scalars().all())

    def list_by_workspace(
        self,
        workspace_id: uuid.UUID,
        *,
        limit: int = _DEFAULT_LIMIT,
        cursor_recorded_at: datetime | None = None,
        cursor_id: uuid.UUID | None = None,
    ) -> list[PilotSignoff]:
        """Workspace-owner view: list sign-offs for a single workspace.

        Fetches limit+1 rows to allow the caller to compute has_more.
        """
        limit = max(1, min(limit, _MAX_LIMIT))
        stmt = select(PilotSignoff).where(
            PilotSignoff.workspace_id == workspace_id
        )

        if cursor_recorded_at is not None and cursor_id is not None:
            stmt = stmt.where(
                (PilotSignoff.recorded_at < cursor_recorded_at)
                | (
                    (PilotSignoff.recorded_at == cursor_recorded_at)
                    & (PilotSignoff.id < cursor_id)
                )
            )

        stmt = (
            stmt.order_by(PilotSignoff.recorded_at.desc(), PilotSignoff.id.desc())
            .limit(limit + 1)
        )
        return list(self._session.execute(stmt).scalars().all())

    def count_workspaces_with_decision(self, decision: str) -> int:
        """Count distinct workspaces whose most-recent sign-off has the given decision."""
        from sqlalchemy import text
        stmt = text(
            "SELECT COUNT(DISTINCT workspace_id) "
            "FROM pilot_signoff ps1 "
            "WHERE decision = :decision "
            "AND recorded_at = ("
            "  SELECT MAX(recorded_at) FROM pilot_signoff ps2 "
            "  WHERE ps2.workspace_id = ps1.workspace_id"
            ")"
        )
        result = self._session.execute(stmt, {"decision": decision}).scalar()
        return int(result or 0)

    def count_distinct_pilot_workspaces(self) -> int:
        """Count distinct workspaces that have at least one sign-off record."""
        from sqlalchemy import text
        stmt = text(
            "SELECT COUNT(DISTINCT workspace_id) FROM pilot_signoff"
        )
        result = self._session.execute(stmt).scalar()
        return int(result or 0)

    def average_accuracy_rating_pct(self) -> int | None:
        """Return percentage of approved/rejected sign-offs rating >= 4 (accurate/actionable).

        Returns None when no rated sign-offs exist.
        The threshold defines 'accurate and actionable' as rating >= 4 out of 5,
        and at least 80% of reviewers must meet that bar.
        """
        from sqlalchemy import text
        stmt = text(
            "SELECT "
            "  COUNT(*) FILTER (WHERE accuracy_actionability_rating >= 4) * 100 / "
            "  NULLIF(COUNT(*) FILTER (WHERE accuracy_actionability_rating IS NOT NULL), 0) "
            "FROM pilot_signoff "
            "WHERE decision IN ('approved', 'rejected')"
        )
        result = self._session.execute(stmt).scalar()
        return int(result) if result is not None else None
