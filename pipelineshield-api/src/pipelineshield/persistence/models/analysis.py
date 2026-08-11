"""Analysis model — pipeline security analysis result.

Data classification: Confidential
Retention: 90 days
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class Analysis(Base):
    """Pipeline security analysis result.

    Stores the scored output of a single analysis run: the 100-point
    security posture score, letter grade, coverage report, and a reference
    to the catalogue version used.  The raw pipeline definition is stored
    separately in pipeline_definition (encrypted).

    Deletion semantics: hard delete only (Confidential).  No deleted_at or
    is_deleted columns are permitted on this table.
    """

    __tablename__ = "analysis"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — analysis identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Owning workspace — tenant scope.",
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="User who initiated the analysis.",
    )
    catalogue_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("control_catalogue_version.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Catalogue version used for scoring.",
    )
    pipeline_format: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "Detected pipeline format: github_actions, gitlab_ci, "
            "jenkins_declarative."
        ),
    )
    format_confidence: Mapped[float] = mapped_column(
        Numeric(4, 3),
        nullable=False,
        comment="Format detection confidence score (0.000–1.000).",
    )
    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Security posture score (0–100).",
    )
    grade: Mapped[str] = mapped_column(
        String(2),
        nullable=False,
        comment="Letter grade derived from score (A, B, C, D, F).",
    )
    coverage_report: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment=(
            "Coverage report listing unresolved fragments and "
            "Not Assessable categories."
        ),
    )
    unscorable_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment=(
            "Populated when all controls are Not Assessable and no "
            "numeric score can be computed."
        ),
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="completed",
        comment=(
            "Analysis lifecycle status: completed, degraded "
            "(model timeout), failed."
        ),
    )
    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment=(
            "Wall-clock milliseconds from analysis start to completion. "
            "Null for analyses created before migration 0006."
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship(  # type: ignore[name-defined]
        back_populates="analyses",
        lazy="raise",
    )
    owner: Mapped["AppUser"] = relationship(  # type: ignore[name-defined]
        foreign_keys=[owner_id],
        lazy="raise",
    )
    catalogue_version: Mapped["ControlCatalogueVersion"] = relationship(  # type: ignore[name-defined]
        back_populates="analyses",
        lazy="raise",
    )
    pipeline_definition: Mapped["PipelineDefinition"] = relationship(  # type: ignore[name-defined]
        back_populates="analysis",
        lazy="raise",
        uselist=False,
    )
    findings: Mapped[list["Finding"]] = relationship(  # type: ignore[name-defined]
        back_populates="analysis",
        lazy="raise",
    )
    generated_drafts: Mapped[list["GeneratedDraft"]] = relationship(  # type: ignore[name-defined]
        back_populates="analysis",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return f"<Analysis id={self.id!r} score={self.score!r} grade={self.grade!r}>"
