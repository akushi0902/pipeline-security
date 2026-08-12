"""Deterministic weighted ScoringEngine.

Converts control-evaluation verdicts into a reproducible 100-point score,
letter grade, and per-category breakdown.  Pure Python — no HTTP, no DB,
no FastAPI imports.

Scoring algorithm (P2 honest-coverage principle):
    1. For each enabled category, iterate member controls.
    2. For each control:
       - PRESENT      → full per-control weight share (weight / len(controls))
       - PARTIAL       → per-control weight share × partial_credit_ratio
       - MISSING       → 0 earned, contributes to denominator
       - NOT_ASSESSABLE → excluded from BOTH numerator and denominator
    3. category subscore  = 100 × (earned / possible)  where possible > 0
    4. total_score        = sum(earned across all categories) / sum(possible)
       expressed as a percentage of the full 100-point scale.
    5. Rounding: Decimal with ROUND_HALF_UP to 1 decimal for display, integer
       comparison for grade bands.

Zero-denominator (all NOT_ASSESSABLE):
    Return a ScoreResult with is_scorable=False rather than raising or
    defaulting to 0/100.

Determinism guarantee:
    Results are computed with decimal.Decimal (ROUND_HALF_UP), not float.
    The input list is iterated in stable category order (from CatalogueView).
    Shuffling the ControlVerdict input list produces identical output.
"""
from __future__ import annotations

import logging
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Sequence

from .catalogue import CatalogueView
from .models import CategoryScore, ControlVerdict, ScoreResult, Verdict

log = logging.getLogger(__name__)

_ZERO = Decimal("0")
_ONE = Decimal("1")
_HUNDRED = Decimal("100")
_QUANTIZE_1DP = Decimal("0.1")


class ScoringError(ValueError):
    """Raised for invalid inputs to ScoringEngine.score()."""


class ScoringEngine:
    """Deterministic, pure scoring engine.

    Instantiate once (e.g. at application startup) and call score() per
    analysis.  Thread-safe — no mutable state.
    """

    def score(
        self,
        verdicts: Sequence[ControlVerdict],
        catalogue: CatalogueView,
    ) -> ScoreResult:
        """Score a set of control verdicts against a catalogue version.

        Args:
            verdicts:  Evaluated control outcomes from the rule engine.
            catalogue: Immutable CatalogueView for the active catalogue version.

        Returns:
            ScoreResult with total_score, letter_grade, per-category breakdown,
            and catalogue_version stamp.

        Raises:
            ScoringError: On unknown control_id, duplicate control_id in verdicts,
                          or control_id/category_id mismatch.
        """
        self._validate_verdicts(verdicts, catalogue)

        # Index verdicts by control_id for O(1) lookup.
        verdict_map: dict[str, Verdict] = {v.control_id: v.verdict for v in verdicts}

        per_category: list[CategoryScore] = []
        total_earned = _ZERO
        total_possible = _ZERO
        total_excluded = 0

        for cat in catalogue.categories:
            cat_score = self._score_category(cat, verdict_map, catalogue)
            per_category.append(cat_score)
            total_earned += cat_score.earned
            total_possible += cat_score.possible
            total_excluded += cat_score.excluded_count

        if total_possible == _ZERO:
            log.info(
                "scoring_unscorable",
                extra={
                    "catalogue_version": catalogue.version,
                    "total_excluded": total_excluded,
                },
            )
            return ScoreResult(
                total_score=None,
                letter_grade=None,
                is_scorable=False,
                unscorable_reason=(
                    "All controls are Not Assessable for this definition; "
                    "no numeric score can be produced."
                ),
                per_category=per_category,
                catalogue_version=catalogue.version,
                total_excluded=total_excluded,
            )

        # total_score is the proportion of total_possible earned, scaled to 100.
        raw_score = (_HUNDRED * total_earned / total_possible).quantize(
            _QUANTIZE_1DP, rounding=ROUND_HALF_UP
        )
        # Clamp to [0, 100] to guard against floating-point edge cases.
        total_score = max(_ZERO, min(_HUNDRED, raw_score))
        letter_grade = self._apply_grade_bands(total_score, catalogue)

        log.info(
            "scoring_complete",
            extra={
                "catalogue_version": catalogue.version,
                "total_score": str(total_score),
                "letter_grade": letter_grade,
                "total_excluded": total_excluded,
            },
        )

        return ScoreResult(
            total_score=total_score,
            letter_grade=letter_grade,
            is_scorable=True,
            per_category=per_category,
            catalogue_version=catalogue.version,
            total_excluded=total_excluded,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _score_category(
        self,
        cat: "Any",
        verdict_map: dict[str, Verdict],
        catalogue: CatalogueView,
    ) -> CategoryScore:
        """Compute earned/possible for one category."""

        n_controls = len(cat.controls)
        if n_controls == 0:
            return CategoryScore(
                category_id=cat.id,
                category_name=cat.name,
                weight=cat.weight,
                earned=_ZERO,
                possible=_ZERO,
                excluded_count=0,
                subscore=None,
            )

        # Per-control weight share (exact Decimal division).
        weight_dec = Decimal(cat.weight)
        per_ctrl_share = weight_dec / Decimal(n_controls)

        earned = _ZERO
        possible = _ZERO
        excluded = 0

        for ctrl in cat.controls:
            v = verdict_map.get(ctrl.id, Verdict.NOT_ASSESSABLE)
            if v == Verdict.NOT_ASSESSABLE:
                excluded += 1
                continue
            possible += per_ctrl_share
            if v == Verdict.PRESENT:
                earned += per_ctrl_share
            elif v == Verdict.PARTIAL:
                earned += per_ctrl_share * catalogue.partial_credit_ratio
            # MISSING → 0 earned, per_ctrl_share already added to possible

        if possible == _ZERO:
            subscore = None
        else:
            subscore = (_HUNDRED * earned / possible).quantize(
                _QUANTIZE_1DP, rounding=ROUND_HALF_UP
            )

        return CategoryScore(
            category_id=cat.id,
            category_name=cat.name,
            weight=cat.weight,
            earned=earned,
            possible=possible,
            excluded_count=excluded,
            subscore=subscore,
        )

    def _apply_grade_bands(
        self, score: Decimal, catalogue: CatalogueView
    ) -> str:
        """Map a numeric score to a letter grade using catalogue grade bands.

        Grade bands use inclusive integer comparison per the documented rule:
        score is rounded to one decimal, then compared with band min/max.
        Band boundaries are integers (0, 60, 70, 80, 90, 100).
        """
        for band in catalogue.grade_bands:
            if band.min_score <= score <= band.max_score:
                return band.grade
        # Fallback: should never be reached with a valid catalogue.
        raise ScoringError(
            f"Score {score} not covered by any grade band in catalogue "
            f"v{catalogue.version}. Grade bands: {catalogue.grade_bands}"
        )

    def _validate_verdicts(
        self,
        verdicts: Sequence[ControlVerdict],
        catalogue: CatalogueView,
    ) -> None:
        """Validate input verdicts before scoring.

        Raises ScoringError for:
        - Duplicate control_id in verdicts.
        - Unknown control_id (not in active catalogue).
        - category_id mismatch between verdict and catalogue.
        """
        seen: set[str] = set()
        for v in verdicts:
            if v.control_id in seen:
                raise ScoringError(
                    f"Duplicate verdict for control_id={v.control_id!r}. "
                    "Each control must appear at most once in the verdict list."
                )
            seen.add(v.control_id)

            if v.control_id not in catalogue.known_control_ids:
                raise ScoringError(
                    f"Unknown control_id={v.control_id!r} not found in catalogue "
                    f"version {catalogue.version}."
                )

            expected_cat = catalogue.control_to_category.get(v.control_id)
            if expected_cat and v.category_id != expected_cat:
                raise ScoringError(
                    f"control_id={v.control_id!r} has category_id={v.category_id!r} "
                    f"in the verdict but category_id={expected_cat!r} in the catalogue."
                )
