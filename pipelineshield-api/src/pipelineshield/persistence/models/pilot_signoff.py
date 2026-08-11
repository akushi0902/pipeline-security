"""PilotSignoff model — append-only pilot workspace sign-off records.

Data classification: Confidential
Retention: 90 days

Append-only invariant: corrections are new records, not updates.
No UPDATE or DELETE path exists through the application layer.
"""
from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, SmallInteger, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .types import DialectTextArray


class PilotSignoff(Base):
    """Append-only pilot workspace sign-off record.

    Each record represents one workspace owner's formal decision on whether
    the pilot is ready for GA.  Corrections must be submitted as new records —
    no UPDATE path exists at the application or database-role level.

    Deletion semantics: hard delete only (Confidential).
    """

    __tablename__ = "pilot_signoff"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — sign-off record identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Owning workspace — tenant scope.",
    )
    reviewer_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_user.id", ondelete="RESTRICT"),
        nullable=False,
        comment="User who submitted this sign-off record.",
    )
    decision: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Sign-off decision: approved, rejected, or pending.",
    )
    accuracy_actionability_rating: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
        comment="Pilot accuracy and actionability rating 1–5.",
    )
    personas_covered: Mapped[list[str]] = mapped_column(
        DialectTextArray(),
        nullable=False,
        default=list,
        comment="Personas represented by this reviewer.",
    )
    comments: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text reviewer comments.",
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Timestamp when this record was committed (UTC).",
    )

    __table_args__ = (
        CheckConstraint(
            "decision IN ('approved', 'rejected', 'pending')",
            name="ck_pilot_signoff_decision",
        ),
        CheckConstraint(
            "accuracy_actionability_rating IS NULL OR "
            "(accuracy_actionability_rating >= 1 AND accuracy_actionability_rating <= 5)",
            name="ck_pilot_signoff_accuracy_rating",
        ),
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship(  # type: ignore[name-defined]
        lazy="raise",
    )
    reviewer: Mapped["AppUser"] = relationship(  # type: ignore[name-defined]
        foreign_keys=[reviewer_user_id],
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<PilotSignoff id={self.id!r} "
            f"workspace_id={self.workspace_id!r} "
            f"decision={self.decision!r}>"
        )
