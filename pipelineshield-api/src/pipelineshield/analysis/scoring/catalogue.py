"""Catalogue loader — materialises an immutable CatalogueView from a snapshot.

The loader reads a versioned catalogue snapshot (from the persistence layer
or from a seed file) and builds an in-memory CatalogueView used exclusively
by the ScoringEngine.  This module imports no HTTP, no SQLAlchemy, and no
FastAPI — it receives already-deserialised data via dependency injection.

Weight-sum validation happens at load time:  if the enabled category weights
do not sum to exactly 100 the application fails closed with a descriptive
CatalogueLoadError.  This prevents a misconfigured catalogue from silently
producing wrong scores.

Partial-credit ratio is stored per catalogue version (default 0.5) so that
Phase-0 ratification can adjust it without a code change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any


class CatalogueLoadError(ValueError):
    """Raised when a catalogue snapshot fails structural validation."""


# ---------------------------------------------------------------------------
# Immutable in-memory representations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CatalogueControl:
    """A single control entry within a category."""

    id: str
    category_id: str
    severity: str
    enabled: bool = True


@dataclass(frozen=True)
class CatalogueCategory:
    """One scoring category with its weight and member controls."""

    id: str
    name: str
    weight: int
    enabled: bool
    controls: tuple[CatalogueControl, ...]


@dataclass(frozen=True)
class GradeBand:
    """Inclusive [min_score, max_score] → letter grade mapping."""

    grade: str
    min_score: Decimal
    max_score: Decimal


@dataclass(frozen=True)
class CatalogueView:
    """Immutable view of one catalogue version, used by ScoringEngine.

    Attributes:
        version:             Integer version label (from the DB row).
        categories:          Enabled categories in stable insertion order.
        grade_bands:         Sorted by min_score ascending.
        partial_credit_ratio: Fractional credit for PARTIAL verdicts (0–1).
        control_to_category: Mapping of control_id → category_id for fast lookup.
        category_map:        Mapping of category_id → CatalogueCategory.
        known_control_ids:   Frozenset of all enabled control IDs.
    """

    version: int
    categories: tuple[CatalogueCategory, ...]
    grade_bands: tuple[GradeBand, ...]
    partial_credit_ratio: Decimal
    control_to_category: dict[str, str]
    category_map: dict[str, CatalogueCategory]
    known_control_ids: frozenset[str]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class CatalogueLoader:
    """Builds a validated CatalogueView from a raw snapshot dict.

    Usage::

        loader = CatalogueLoader()
        view = loader.load(version=1, snapshot=raw_dict, partial_credit_ratio=0.5)

    ``snapshot`` is the dict produced by ``CatalogueSnapshot.model_dump()``.
    ``grade_bands`` may be embedded in ``snapshot`` or supplied separately.
    ``partial_credit_ratio`` defaults to Decimal("0.5") and is stored on the
    catalogue version row so changing it requires a new version, not a code
    change.
    """

    def load(
        self,
        version: int,
        snapshot: dict[str, Any],
        partial_credit_ratio: Decimal | float | str = Decimal("0.5"),
        grade_bands_override: list[dict[str, Any]] | None = None,
    ) -> CatalogueView:
        """Load and validate a catalogue snapshot into a CatalogueView.

        Args:
            version:               Catalogue version integer.
            snapshot:              Raw snapshot dict (categories + grade_bands).
            partial_credit_ratio:  Credit for PARTIAL verdicts; default 0.5.
            grade_bands_override:  Supply grade bands separately if not in snapshot.

        Returns:
            Validated CatalogueView ready for use by ScoringEngine.

        Raises:
            CatalogueLoadError: If weights don't sum to 100, IDs are non-unique,
                                or grade bands don't cover 0–100.
        """
        ratio = Decimal(str(partial_credit_ratio))
        if not (Decimal("0") <= ratio <= Decimal("1")):
            raise CatalogueLoadError(
                f"partial_credit_ratio must be in [0, 1]; got {ratio}"
            )

        raw_categories: list[dict[str, Any]] = snapshot.get("categories", [])
        raw_grade_bands: list[dict[str, Any]] = (
            grade_bands_override
            or snapshot.get("grade_bands", [])
        )

        categories = self._parse_categories(raw_categories)
        grade_bands = self._parse_grade_bands(raw_grade_bands)
        self._validate_weight_sum(categories)
        self._validate_unique_ids(categories)

        control_to_cat: dict[str, str] = {}
        category_map: dict[str, CatalogueCategory] = {}
        known_ids: set[str] = set()
        for cat in categories:
            category_map[cat.id] = cat
            for ctrl in cat.controls:
                control_to_cat[ctrl.id] = cat.id
                known_ids.add(ctrl.id)

        return CatalogueView(
            version=version,
            categories=tuple(categories),
            grade_bands=tuple(sorted(grade_bands, key=lambda b: b.min_score)),
            partial_credit_ratio=ratio,
            control_to_category=control_to_cat,
            category_map=category_map,
            known_control_ids=frozenset(known_ids),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_categories(
        self, raw: list[dict[str, Any]]
    ) -> list[CatalogueCategory]:
        categories: list[CatalogueCategory] = []
        for c in raw:
            if not c.get("enabled", True):
                continue
            controls = tuple(
                CatalogueControl(
                    id=ctrl["id"],
                    category_id=ctrl["category_id"],
                    severity=ctrl.get("severity", "info"),
                    enabled=ctrl.get("enabled", True),
                )
                for ctrl in c.get("controls", [])
                if ctrl.get("enabled", True)
            )
            categories.append(
                CatalogueCategory(
                    id=c["id"],
                    name=c.get("name", c["id"]),
                    weight=int(c["weight"]),
                    enabled=True,
                    controls=controls,
                )
            )
        return categories

    def _parse_grade_bands(
        self, raw: list[dict[str, Any]]
    ) -> list[GradeBand]:
        if not raw:
            raise CatalogueLoadError("Catalogue must define at least one grade band.")
        bands: list[GradeBand] = []
        for b in raw:
            bands.append(
                GradeBand(
                    grade=b["grade"],
                    min_score=Decimal(str(b["min_score"])),
                    max_score=Decimal(str(b["max_score"])),
                )
            )
        return bands

    def _validate_weight_sum(self, categories: list[CatalogueCategory]) -> None:
        total = sum(c.weight for c in categories)
        if total != 100:
            raise CatalogueLoadError(
                f"Enabled category weights must sum to exactly 100; got {total}. "
                "Fix the catalogue seed before running the application."
            )

    def _validate_unique_ids(self, categories: list[CatalogueCategory]) -> None:
        cat_ids: list[str] = [c.id for c in categories]
        if len(cat_ids) != len(set(cat_ids)):
            seen: set[str] = set()
            dupes = {i for i in cat_ids if i in seen or seen.add(i)}  # type: ignore[func-returns-value]
            raise CatalogueLoadError(f"Duplicate category IDs: {sorted(dupes)}")

        ctrl_ids: list[str] = [
            ctrl.id for cat in categories for ctrl in cat.controls
        ]
        if len(ctrl_ids) != len(set(ctrl_ids)):
            seen2: set[str] = set()
            dupes2 = {i for i in ctrl_ids if i in seen2 or seen2.add(i)}  # type: ignore[func-returns-value]
            raise CatalogueLoadError(f"Duplicate control IDs: {sorted(dupes2)}")
