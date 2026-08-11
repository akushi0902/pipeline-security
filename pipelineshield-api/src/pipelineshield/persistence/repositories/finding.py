"""FindingRepository — abstract interface and SQLAlchemy implementation."""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.finding import Finding


class FindingRepository(ABC):
    """Abstract repository interface for Finding entities.

    Row-level scoping by workspace_id is applied inside repository methods.
    """

    @abstractmethod
    def get_by_id(
        self, finding_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> Finding | None:
        """Return the finding with *finding_id* within *workspace_id*, or None."""

    @abstractmethod
    def list_by_analysis(
        self,
        analysis_id: uuid.UUID,
        workspace_id: uuid.UUID,
        *,
        source: str | None = None,
    ) -> Sequence[Finding]:
        """Return findings for *analysis_id*, optionally filtered by *source*."""

    @abstractmethod
    def add(self, finding: Finding) -> Finding:
        """Persist a new Finding and return the managed instance."""

    @abstractmethod
    def add_many(self, findings: list[Finding]) -> list[Finding]:
        """Bulk-persist a list of Findings."""

    @abstractmethod
    def delete(self, finding: Finding) -> None:
        """Hard-delete *finding*.  No soft-delete path exists."""


class SQLAlchemyFindingRepository(FindingRepository):
    """SQLAlchemy 2.0 implementation of FindingRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(
        self, finding_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> Finding | None:
        stmt = select(Finding).where(
            Finding.id == finding_id,
            Finding.workspace_id == workspace_id,
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def list_by_analysis(
        self,
        analysis_id: uuid.UUID,
        workspace_id: uuid.UUID,
        *,
        source: str | None = None,
    ) -> Sequence[Finding]:
        stmt = select(Finding).where(
            Finding.analysis_id == analysis_id,
            Finding.workspace_id == workspace_id,
        )
        if source is not None:
            stmt = stmt.where(Finding.source == source)
        stmt = stmt.order_by(Finding.created_at)
        return self._session.execute(stmt).scalars().all()

    def add(self, finding: Finding) -> Finding:
        self._session.add(finding)
        self._session.flush()
        return finding

    def add_many(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            self._session.add(f)
        self._session.flush()
        return findings

    def delete(self, finding: Finding) -> None:
        self._session.delete(finding)
        self._session.flush()
