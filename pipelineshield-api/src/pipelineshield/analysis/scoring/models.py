"""Pydantic v2 models for the scoring engine public contract.

These models form the boundary between the deterministic analysis core and the
persistence / API layers.  They must import no HTTP, no database, and no
framework modules — only the standard library and Pydantic.

Verdict semantics:
    PRESENT        Control is implemented correctly.   Full credit.
    PARTIAL        Control is partly implemented.      Fractional credit (default 0.5).
    MISSING        Control is absent.                  Zero credit.
    NOT_ASSESSABLE Control cannot be evaluated for this definition (unresolved
                   include, scripted Groovy, etc.).  Excluded from both
                   numerator AND denominator — not penalised, not rewarded.
"""
from __future__ import annotations

import enum
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Verdict(str, enum.Enum):
    """Deterministic control-evaluation outcome."""

    PRESENT = "present"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_ASSESSABLE = "not_assessable"


class ControlVerdict(BaseModel):
    """Evaluation outcome for a single security control.

    Produced by the rule engine and consumed by the ScoringEngine.

    Attributes:
        control_id:        Catalogue control identifier (e.g. ``sh-001``).
        category_id:       Owning category identifier (e.g. ``secrets_hygiene``).
        verdict:           One of PRESENT, PARTIAL, MISSING, NOT_ASSESSABLE.
        evidence_anchor_ref: Optional reference to the source line that
                           justifies the verdict (line number or anchor id).
    """

    control_id: str = Field(..., min_length=1, max_length=64)
    category_id: str = Field(..., min_length=1, max_length=64)
    verdict: Verdict
    evidence_anchor_ref: str | None = None

    model_config = {"frozen": True}


class CategoryScore(BaseModel):
    """Aggregated score for one control category.

    ``possible`` is the maximum earnable points for this category after
    excluding NOT_ASSESSABLE controls from the denominator.  ``earned`` is
    the actual points earned.  ``subscore`` is the percentage (0–100) of
    the category's weight earned, or None when possible == 0 (all excluded).

    Attributes:
        category_id:    Catalogue category identifier.
        category_name:  Human-readable name.
        weight:         Category weight as configured in the active catalogue.
        earned:         Decimal points earned (Decimal, not float).
        possible:       Decimal maximum earnable points (denominator contribution).
        excluded_count: Number of controls excluded as NOT_ASSESSABLE.
        subscore:       Percentage of weight earned, or None when unscorable.
    """

    category_id: str
    category_name: str
    weight: int
    earned: Decimal
    possible: Decimal
    excluded_count: int = 0
    subscore: Decimal | None = None  # None == not assessable for this category

    model_config = {"frozen": True, "arbitrary_types_allowed": True}


class ScoreResult(BaseModel):
    """Complete scoring output for one analysis run.

    The contract consumed by WO-021 (report assembly) and persisted to the
    ``analysis`` and ``analysis_category_score`` tables.

    Attributes:
        total_score:       Weighted 0–100 score, or None when unscorable.
        letter_grade:      Grade band letter (A/B/C/D/F), or None when unscorable.
        is_scorable:       False when denominator is zero (all NOT_ASSESSABLE).
        unscorable_reason: Human-readable explanation when ``is_scorable`` is False.
        per_category:      Per-category breakdown (always present).
        catalogue_version: Integer version label of the catalogue used.
        total_excluded:    Total NOT_ASSESSABLE controls across all categories.
    """

    total_score: Decimal | None = None
    letter_grade: str | None = None
    is_scorable: bool = True
    unscorable_reason: str | None = None
    per_category: list[CategoryScore] = Field(default_factory=list)
    catalogue_version: int
    total_excluded: int = 0

    model_config = {"frozen": True, "arbitrary_types_allowed": True}

    @model_validator(mode="after")
    def _unscorable_consistency(self) -> "ScoreResult":
        if not self.is_scorable:
            if self.total_score is not None or self.letter_grade is not None:
                raise ValueError(
                    "is_scorable=False must have total_score=None and letter_grade=None"
                )
        else:
            if self.total_score is None or self.letter_grade is None:
                raise ValueError(
                    "is_scorable=True must have total_score and letter_grade set"
                )
        return self

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict (for determinism testing)."""
        return {
            "total_score": str(self.total_score) if self.total_score is not None else None,
            "letter_grade": self.letter_grade,
            "is_scorable": self.is_scorable,
            "unscorable_reason": self.unscorable_reason,
            "catalogue_version": self.catalogue_version,
            "total_excluded": self.total_excluded,
            "per_category": sorted(
                [
                    {
                        "category_id": c.category_id,
                        "earned": str(c.earned),
                        "possible": str(c.possible),
                        "excluded_count": c.excluded_count,
                        "subscore": str(c.subscore) if c.subscore is not None else None,
                    }
                    for c in self.per_category
                ],
                key=lambda x: x["category_id"],
            ),
        }
