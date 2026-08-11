"""RetentionPolicy model — workspace retention configuration.

Data classification: Internal
Retention: indefinite

Single-row table (id=1 enforced by CHECK constraint).  The row is created
by the Alembic migration and updated via PUT /governance/retention-policy,
which always emits an audit_event recording the before/after values.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, SmallInteger, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class RetentionPolicy(Base):
    """Workspace-level data retention configuration.

    Enforces a single-row constraint (id = 1) so there is exactly one active
    policy at a time.  Concurrent writes are last-write-wins; both writes are
    fully recorded in the audit log.

    Maximum retention_days = 90, reflecting the 90-day policy maximum for
    Confidential entities.
    """

    __tablename__ = "retention_policy"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_retention_policy_single_row"),
        CheckConstraint(
            "retention_days >= 1 AND retention_days <= 90",
            name="ck_retention_policy_days_range",
        ),
    )

    id: Mapped[int] = mapped_column(
        SmallInteger(),
        primary_key=True,
        default=1,
        comment="Always 1 — single-row sentinel enforced by CHECK constraint.",
    )
    retention_days: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
        default=90,
        comment="Number of days Confidential data is retained before purge (1–90).",
    )
    updated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="UUID of the AppUser who last updated this policy.",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Timestamp of the last policy update (UTC).",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    def __repr__(self) -> str:
        return (
            f"<RetentionPolicy retention_days={self.retention_days!r} "
            f"updated_by={self.updated_by!r}>"
        )
