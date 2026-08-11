"""AuditRepository — abstract interface and SQLAlchemy implementation.

The audit_event table is append-only.  This repository exposes only INSERT
and SELECT operations — there are no update or delete methods.

INVARIANT: change_detail MUST NEVER contain definition content or secret
values.  This is enforced by convention and code review.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.audit_event import AuditEvent


class AuditRepository(ABC):
    """Abstract repository for AuditEvent — append-only operations only.

    No update or delete methods are provided.  The database role enforces this
    constraint at the privilege level; the Python interface reinforces it.
    """

    @abstractmethod
    def append(self, event: AuditEvent) -> AuditEvent:
        """Append a new audit event record and return the managed instance.

        This is the only write method — there is no update or delete.
        """

    @abstractmethod
    def list_by_resource(
        self,
        resource_type: str,
        resource_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        """Return audit events for a specific resource, newest first."""

    @abstractmethod
    def list_by_actor(
        self,
        actor_id: str,
        *,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        """Return audit events for a specific actor, newest first."""


class SQLAlchemyAuditRepository(AuditRepository):
    """SQLAlchemy 2.0 implementation of AuditRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: AuditEvent) -> AuditEvent:
        self._session.add(event)
        self._session.flush()
        return event

    def list_by_resource(
        self,
        resource_type: str,
        resource_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        stmt = (
            select(AuditEvent)
            .where(
                AuditEvent.resource_type == resource_type,
                AuditEvent.resource_id == resource_id,
            )
            .order_by(AuditEvent.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._session.execute(stmt).scalars().all()

    def list_by_actor(
        self,
        actor_id: str,
        *,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        stmt = select(AuditEvent).where(AuditEvent.actor_id == actor_id)
        if since is not None:
            stmt = stmt.where(AuditEvent.occurred_at >= since)
        stmt = (
            stmt.order_by(AuditEvent.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._session.execute(stmt).scalars().all()
