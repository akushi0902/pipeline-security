"""AnalysisCategoryScore model — per-category score breakdown.

Data classification: Confidential
Retention: 90 days (cascades with parent analysis row)
"""
from __future__ import annotations

import uuid
from decimal import Decimal

from sqlalchemy import ForeignKey, Integer, Numeric, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class AnalysisCategoryScore(Base):
    """Per-category scoring breakdown for one analysis run.

    Each row records the earned/possible breakdown for a single control
    category within one analysis.  Rows are created atomically with the
    parent analysis and cascade-deleted with it.
    """

    __tablename__ = "analysis_category_score"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key.",
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Parent analysis.",
    )
    category_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Catalogue category identifier.",
    )
    category_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable category name at time of scoring.",
    )
    weight: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Category weight as configured in the active catalogue.",
    )
    earned: Mapped[Decimal] = mapped_column(
        Numeric(8, 4),
        nullable=False,
        comment="Decimal points earned for this category.",
    )
    possible: Mapped[Decimal] = mapped_column(
        Numeric(8, 4),
        nullable=False,
        comment="Maximum earnable points after Not-Assessable exclusion.",
    )
    excluded_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of controls excluded as Not Assessable.",
    )
    subscore: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2),
        nullable=True,
        comment="Category subscore percentage; null when all controls are NA.",
    )

    # Relationship back to Analysis is omitted here to avoid circular import;
    # Analysis declares the relationship via back_populates if needed.

    def __repr__(self) -> str:
        return (
            f"<AnalysisCategoryScore analysis_id={self.analysis_id!r} "
            f"category={self.category_id!r} subscore={self.subscore!r}>"
        )
