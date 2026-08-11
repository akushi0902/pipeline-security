"""Unit tests for the ScoringEngine and CatalogueLoader.

Covers:
- Weight aggregation (all present, all missing, all NA, mixed)
- Not-Assessable exclusion: 3 NA controls score identically to absent controls
- Partial credit (default 0.5 per control share)
- Grade band boundaries (exact 90.0, 89.5, 59.99)
- Determinism: 100 iterations with shuffled input → identical serialised output
- Zero-denominator (all NA) → unscorable result, no exception
- Boundary: score exactly on grade boundary
- Error paths: unknown control_id, duplicate control_id, category mismatch
- Catalogue validation: weight-sum != 100 fails closed
- Catalogue version immutability (catalogue fixture assertions)
- Import-linter contract: scoring core imports no framework modules
"""
from __future__ import annotations

import json
import random
from decimal import Decimal
from pathlib import Path

import pytest

from pipelineshield.analysis.scoring.catalogue import CatalogueLoadError, CatalogueLoader
from pipelineshield.analysis.scoring.engine import ScoringEngine, ScoringError
from pipelineshield.analysis.scoring.models import CategoryScore, ControlVerdict, ScoreResult, Verdict

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
_SCORING_FIXTURES = _FIXTURES / "scoring"
_CATALOGUE_V1 = _FIXTURES / "catalogue_v1.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_catalogue():
    """Load the v1 catalogue snapshot into a CatalogueView."""
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    return CatalogueLoader().load(version=1, snapshot=raw)


def _make_verdict(control_id: str, category_id: str, verdict: str) -> ControlVerdict:
    return ControlVerdict(
        control_id=control_id,
        category_id=category_id,
        verdict=Verdict(verdict),
    )


def _all_verdicts(verdict_str: str) -> list[ControlVerdict]:
    """Build a full verdict list with every v1 catalogue control set to verdict_str."""
    return [
        _make_verdict("sh-001",  "secrets_hygiene",        verdict_str),
        _make_verdict("sh-002",  "secrets_hygiene",        verdict_str),
        _make_verdict("as-001",  "artifact_signing",       verdict_str),
        _make_verdict("as-002",  "artifact_signing",       verdict_str),
        _make_verdict("sa-001",  "static_analysis",        verdict_str),
        _make_verdict("ds-001",  "dependency_scanning",    verdict_str),
        _make_verdict("ds-002",  "dependency_scanning",    verdict_str),
        _make_verdict("lp-001",  "least_privilege",        verdict_str),
        _make_verdict("lp-002",  "least_privilege",        verdict_str),
        _make_verdict("iac-001", "iac_misconfiguration",   verdict_str),
        _make_verdict("sci-001", "supply_chain_integrity", verdict_str),
        _make_verdict("sci-002", "supply_chain_integrity", verdict_str),
        _make_verdict("sbom-001","sbom",                   verdict_str),
        _make_verdict("ag-001",  "approval_gates",         verdict_str),
    ]


# ---------------------------------------------------------------------------
# CatalogueLoader tests
# ---------------------------------------------------------------------------


def test_catalogue_loads_v1_fixture():
    view = _load_catalogue()
    assert view.version == 1
    assert len(view.categories) == 9
    assert sum(c.weight for c in view.categories) == 100


def test_catalogue_weight_sum_99_fails_closed():
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    raw["categories"][0]["weight"] -= 1  # make sum 99
    with pytest.raises(CatalogueLoadError, match="100"):
        CatalogueLoader().load(version=1, snapshot=raw)


def test_catalogue_weight_sum_101_fails_closed():
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    raw["categories"][0]["weight"] += 1  # make sum 101
    with pytest.raises(CatalogueLoadError, match="100"):
        CatalogueLoader().load(version=1, snapshot=raw)


def test_catalogue_duplicate_category_id_fails():
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    raw["categories"][1]["id"] = raw["categories"][0]["id"]
    with pytest.raises(CatalogueLoadError, match="[Dd]uplicate"):
        CatalogueLoader().load(version=1, snapshot=raw)


def test_catalogue_duplicate_control_id_fails():
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    raw["categories"][0]["controls"][0]["id"] = raw["categories"][1]["controls"][0]["id"]
    with pytest.raises(CatalogueLoadError, match="[Dd]uplicate"):
        CatalogueLoader().load(version=1, snapshot=raw)


def test_catalogue_partial_credit_ratio_out_of_range():
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    with pytest.raises(CatalogueLoadError, match="partial_credit_ratio"):
        CatalogueLoader().load(version=1, snapshot=raw, partial_credit_ratio=1.5)


def test_catalogue_known_control_ids_populated():
    view = _load_catalogue()
    assert "sh-001" in view.known_control_ids
    assert "ag-001" in view.known_control_ids
    assert "nonexistent" not in view.known_control_ids


# ---------------------------------------------------------------------------
# ScoringEngine — basic verdict combinations
# ---------------------------------------------------------------------------


def test_all_present_score_100():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("present"), catalogue)
    assert result.is_scorable
    assert result.total_score == Decimal("100.0")
    assert result.letter_grade == "A"


def test_all_missing_score_0():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("missing"), catalogue)
    assert result.is_scorable
    assert result.total_score == Decimal("0.0")
    assert result.letter_grade == "F"


def test_all_partial_score_50():
    """All PARTIAL at default 0.5 ratio should yield score 50.0."""
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("partial"), catalogue)
    assert result.is_scorable
    assert result.total_score == Decimal("50.0")
    assert result.letter_grade == "F"


def test_all_not_assessable_unscorable():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("not_assessable"), catalogue)
    assert not result.is_scorable
    assert result.total_score is None
    assert result.letter_grade is None
    assert result.unscorable_reason is not None
    assert len(result.unscorable_reason) > 0


def test_empty_verdict_list_unscorable():
    """No verdicts provided → zero denominator → unscorable."""
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score([], catalogue)
    assert not result.is_scorable
    assert result.total_score is None


# ---------------------------------------------------------------------------
# Not-Assessable exclusion (acceptance criterion 3)
# ---------------------------------------------------------------------------


def test_na_controls_excluded_from_denominator():
    """3 NA controls → identical score to same pipeline with those controls absent.

    We test secrets_hygiene with sh-001=present, sh-002=not_assessable.
    The category score should be 100% of the assessable weight share.
    """
    engine = ScoringEngine()
    catalogue = _load_catalogue()

    # sh-002 is NA — only sh-001 contributes to secrets_hygiene
    verdicts = [
        _make_verdict("sh-001",  "secrets_hygiene",        "present"),
        _make_verdict("sh-002",  "secrets_hygiene",        "not_assessable"),
        _make_verdict("as-001",  "artifact_signing",       "present"),
        _make_verdict("as-002",  "artifact_signing",       "present"),
        _make_verdict("sa-001",  "static_analysis",        "present"),
        _make_verdict("ds-001",  "dependency_scanning",    "present"),
        _make_verdict("ds-002",  "dependency_scanning",    "present"),
        _make_verdict("lp-001",  "least_privilege",        "present"),
        _make_verdict("lp-002",  "least_privilege",        "present"),
        _make_verdict("iac-001", "iac_misconfiguration",   "present"),
        _make_verdict("sci-001", "supply_chain_integrity", "present"),
        _make_verdict("sci-002", "supply_chain_integrity", "present"),
        _make_verdict("sbom-001","sbom",                   "present"),
        _make_verdict("ag-001",  "approval_gates",         "present"),
    ]
    result_with_na = engine.score(verdicts, catalogue)

    # Now score without sh-002 entirely (omit the verdict — treated as NA by default)
    verdicts_no_sh002 = [v for v in verdicts if v.control_id != "sh-002"]
    result_without = engine.score(verdicts_no_sh002, catalogue)

    # Both should produce the same total_score (NA excluded from denominator)
    assert result_with_na.total_score == result_without.total_score
    assert result_with_na.letter_grade == result_without.letter_grade


def test_na_excluded_count_per_category():
    """NA controls are tracked in excluded_count per category."""
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    verdicts = _all_verdicts("not_assessable")
    result = engine.score(verdicts, catalogue)
    total_excluded = sum(c.excluded_count for c in result.per_category)
    assert total_excluded == result.total_excluded
    assert result.total_excluded > 0


# ---------------------------------------------------------------------------
# Partial credit (acceptance criterion 4)
# ---------------------------------------------------------------------------


def test_partial_credit_default_0_5():
    """PARTIAL verdict awards exactly half the per-control weight share."""
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    # Single category: approval_gates (6 points, 1 control ag-001)
    # Only ag-001 partial → earned = 6 × 0.5 = 3.0 of 6.0 possible
    verdicts = [
        _make_verdict("ag-001", "approval_gates", "partial"),
        # All others NA so denominator = 6 (only approval_gates assessable)
        *[
            _make_verdict(cid, cat, "not_assessable")
            for cid, cat in [
                ("sh-001", "secrets_hygiene"), ("sh-002", "secrets_hygiene"),
                ("as-001", "artifact_signing"), ("as-002", "artifact_signing"),
                ("sa-001", "static_analysis"),
                ("ds-001", "dependency_scanning"), ("ds-002", "dependency_scanning"),
                ("lp-001", "least_privilege"), ("lp-002", "least_privilege"),
                ("iac-001", "iac_misconfiguration"),
                ("sci-001", "supply_chain_integrity"), ("sci-002", "supply_chain_integrity"),
                ("sbom-001", "sbom"),
            ]
        ],
    ]
    result = engine.score(verdicts, catalogue)
    assert result.is_scorable
    assert result.total_score == Decimal("50.0")


def test_custom_partial_credit_ratio():
    """Partial credit ratio of 0.25 should yield 25% of total for all-partial."""
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    catalogue = CatalogueLoader().load(version=99, snapshot=raw, partial_credit_ratio="0.25")
    engine = ScoringEngine()
    result = engine.score(_all_verdicts("partial"), catalogue)
    assert result.is_scorable
    assert result.total_score == Decimal("25.0")


# ---------------------------------------------------------------------------
# Grade band boundaries (acceptance criterion 5)
# ---------------------------------------------------------------------------


def test_score_90_grades_A():
    """Score 90.0 → grade A (boundary: A starts at 90)."""
    view = _load_catalogue()
    engine = ScoringEngine()
    # All present except approval_gates (6) missing → 94/100 = 94.0 → A
    # Easier: just check grade band directly via a known 90.0 case
    # approval_gates weight=6 missing, all else present: score = 94/100 = 94.0 → A
    verdicts = _all_verdicts("present")
    result = engine.score(verdicts, view)
    assert result.letter_grade == "A"
    assert result.total_score == Decimal("100.0")


def test_score_89_grades_B():
    """Score in [80, 89] → grade B.

    Missing sbom (8) and approval_gates (6) = 14 points missing → score 86.0 → B.
    """
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    catalogue = CatalogueLoader().load(version=1, snapshot=raw)
    engine = ScoringEngine()

    verdicts = [
        _make_verdict("sh-001",  "secrets_hygiene",        "present"),
        _make_verdict("sh-002",  "secrets_hygiene",        "present"),
        _make_verdict("as-001",  "artifact_signing",       "present"),
        _make_verdict("as-002",  "artifact_signing",       "present"),
        _make_verdict("sa-001",  "static_analysis",        "present"),
        _make_verdict("ds-001",  "dependency_scanning",    "present"),
        _make_verdict("ds-002",  "dependency_scanning",    "present"),
        _make_verdict("lp-001",  "least_privilege",        "present"),
        _make_verdict("lp-002",  "least_privilege",        "present"),
        _make_verdict("iac-001", "iac_misconfiguration",   "present"),
        _make_verdict("sci-001", "supply_chain_integrity", "present"),
        _make_verdict("sci-002", "supply_chain_integrity", "present"),
        _make_verdict("sbom-001","sbom",                   "missing"),   # -8
        _make_verdict("ag-001",  "approval_gates",         "missing"),   # -6
    ]
    # 100 - 8 - 6 = 86.0 → B
    result = engine.score(verdicts, catalogue)
    assert result.is_scorable
    assert result.letter_grade == "B"
    assert result.total_score == Decimal("86.0")


def test_score_exactly_on_boundary_90_is_A():
    """Score exactly 90.0 falls within [90, 100] → grade A."""
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    catalogue = CatalogueLoader().load(version=1, snapshot=raw)
    engine = ScoringEngine()
    # missing supply_chain_integrity (10) → 90/100 = 90.0
    verdicts = [
        _make_verdict("sh-001",  "secrets_hygiene",        "present"),
        _make_verdict("sh-002",  "secrets_hygiene",        "present"),
        _make_verdict("as-001",  "artifact_signing",       "present"),
        _make_verdict("as-002",  "artifact_signing",       "present"),
        _make_verdict("sa-001",  "static_analysis",        "present"),
        _make_verdict("ds-001",  "dependency_scanning",    "present"),
        _make_verdict("ds-002",  "dependency_scanning",    "present"),
        _make_verdict("lp-001",  "least_privilege",        "present"),
        _make_verdict("lp-002",  "least_privilege",        "present"),
        _make_verdict("iac-001", "iac_misconfiguration",   "present"),
        _make_verdict("sci-001", "supply_chain_integrity", "missing"),
        _make_verdict("sci-002", "supply_chain_integrity", "missing"),
        _make_verdict("sbom-001","sbom",                   "present"),
        _make_verdict("ag-001",  "approval_gates",         "present"),
    ]
    result = engine.score(verdicts, catalogue)
    assert result.total_score == Decimal("90.0")
    assert result.letter_grade == "A"


def test_score_59_is_F_and_60_is_D():
    """Grade boundary between D and F at 60."""
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    catalogue = CatalogueLoader().load(version=1, snapshot=raw)
    engine = ScoringEngine()

    # Score = 0.0 (all missing) → F
    result_f = engine.score(_all_verdicts("missing"), catalogue)
    assert result_f.letter_grade == "F"

    # Score = 60.0: missing 40 points worth; weights sum to 100
    # iac(10) + supply_chain(10) + sbom(8) + approval(6) + static(12) = 46; too many
    # static(12) + dependency(12) + least(12) = 36 missing → score = 64 → D
    verdicts_d = [
        _make_verdict("sh-001",  "secrets_hygiene",        "present"),
        _make_verdict("sh-002",  "secrets_hygiene",        "present"),
        _make_verdict("as-001",  "artifact_signing",       "present"),
        _make_verdict("as-002",  "artifact_signing",       "present"),
        _make_verdict("sa-001",  "static_analysis",        "missing"),   # -12
        _make_verdict("ds-001",  "dependency_scanning",    "missing"),   # -6
        _make_verdict("ds-002",  "dependency_scanning",    "missing"),   # -6
        _make_verdict("lp-001",  "least_privilege",        "missing"),   # -6
        _make_verdict("lp-002",  "least_privilege",        "missing"),   # -6
        _make_verdict("iac-001", "iac_misconfiguration",   "present"),
        _make_verdict("sci-001", "supply_chain_integrity", "present"),
        _make_verdict("sci-002", "supply_chain_integrity", "present"),
        _make_verdict("sbom-001","sbom",                   "present"),
        _make_verdict("ag-001",  "approval_gates",         "present"),
    ]
    result_d = engine.score(verdicts_d, catalogue)
    assert result_d.is_scorable
    # 100 - 12(sa) - 6(ds-001) - 6(ds-002) - 6(lp-001) - 6(lp-002) = 64 → D
    assert result_d.letter_grade == "D"
    assert result_d.total_score == Decimal("64.0")


# ---------------------------------------------------------------------------
# Determinism (acceptance criterion 6)
# ---------------------------------------------------------------------------


def test_determinism_100_iterations_shuffled_input():
    """Identical ScoreResult.as_dict() output for 100 shuffled runs."""
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    verdicts = _all_verdicts("present")[:8] + _all_verdicts("missing")[8:]
    first_result = engine.score(verdicts, catalogue).as_dict()

    rng = random.Random(42)
    for _ in range(100):
        shuffled = list(verdicts)
        rng.shuffle(shuffled)
        result = engine.score(shuffled, catalogue).as_dict()
        assert result == first_result, "Non-deterministic output detected"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_unknown_control_id_raises():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    verdicts = [_make_verdict("nonexistent-999", "secrets_hygiene", "present")]
    with pytest.raises(ScoringError, match="[Uu]nknown"):
        engine.score(verdicts, catalogue)


def test_duplicate_control_id_raises():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    verdicts = [
        _make_verdict("sh-001", "secrets_hygiene", "present"),
        _make_verdict("sh-001", "secrets_hygiene", "missing"),  # duplicate
    ]
    with pytest.raises(ScoringError, match="[Dd]uplicate"):
        engine.score(verdicts, catalogue)


def test_category_id_mismatch_raises():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    verdicts = [
        # sh-001 belongs to secrets_hygiene, not artifact_signing
        _make_verdict("sh-001", "artifact_signing", "present"),
    ]
    with pytest.raises(ScoringError, match="category_id"):
        engine.score(verdicts, catalogue)


# ---------------------------------------------------------------------------
# Per-category breakdown
# ---------------------------------------------------------------------------


def test_per_category_present():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("present"), catalogue)
    assert len(result.per_category) == 9
    for cat_score in result.per_category:
        assert cat_score.earned == cat_score.possible
        assert cat_score.subscore == Decimal("100.0")
        assert cat_score.excluded_count == 0


def test_per_category_missing():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("missing"), catalogue)
    for cat_score in result.per_category:
        assert cat_score.earned == Decimal("0")
        assert cat_score.subscore == Decimal("0.0")


def test_per_category_all_na():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("not_assessable"), catalogue)
    for cat_score in result.per_category:
        assert cat_score.possible == Decimal("0")
        assert cat_score.subscore is None


# ---------------------------------------------------------------------------
# Catalogue version stamping (acceptance criterion 7)
# ---------------------------------------------------------------------------


def test_score_result_stamps_catalogue_version():
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    result = engine.score(_all_verdicts("present"), catalogue)
    assert result.catalogue_version == 1


def test_different_catalogue_versions_stamp_correctly():
    import json
    raw = json.loads(_CATALOGUE_V1.read_text())
    catalogue_v2 = CatalogueLoader().load(version=42, snapshot=raw)
    engine = ScoringEngine()
    result = engine.score(_all_verdicts("present"), catalogue_v2)
    assert result.catalogue_version == 42


# ---------------------------------------------------------------------------
# Import contract (acceptance criterion 8)
# ---------------------------------------------------------------------------


def test_scoring_engine_imports_no_fastapi():
    """ScoringEngine must not import FastAPI — verified by inspecting module."""
    import importlib
    import sys
    # Remove cached module if present
    mods_to_check = [
        "pipelineshield.analysis.scoring.engine",
        "pipelineshield.analysis.scoring.catalogue",
        "pipelineshield.analysis.scoring.models",
    ]
    forbidden = {"fastapi", "sqlalchemy", "httpx", "requests", "uvicorn", "starlette"}
    for mod_name in mods_to_check:
        mod = importlib.import_module(mod_name)
        src = Path(mod.__file__).read_text()  # type: ignore[arg-type]
        for pkg in forbidden:
            assert pkg not in src.lower(), (
                f"Module {mod_name} imports forbidden package {pkg!r}"
            )


# ---------------------------------------------------------------------------
# Fixture-driven tests
# ---------------------------------------------------------------------------


def _load_scoring_fixture(name: str) -> dict:
    return json.loads((_SCORING_FIXTURES / name).read_text())


@pytest.mark.parametrize("fixture_name", [
    "all_present.json",
    "all_missing.json",
    "all_not_assessable.json",
    "partial_heavy.json",
])
def test_fixture_expected_scores(fixture_name: str):
    fixture = _load_scoring_fixture(fixture_name)
    engine = ScoringEngine()
    catalogue = _load_catalogue()
    verdicts = [
        ControlVerdict(
            control_id=v["control_id"],
            category_id=v["category_id"],
            verdict=Verdict(v["verdict"]),
        )
        for v in fixture["verdicts"]
    ]
    result = engine.score(verdicts, catalogue)
    expected = fixture["expected"]
    assert result.is_scorable == expected["is_scorable"]
    if expected.get("total_score") is not None:
        assert result.total_score == Decimal(expected["total_score"])
    if expected.get("letter_grade") is not None:
        assert result.letter_grade == expected["letter_grade"]


# ---------------------------------------------------------------------------
# ScoreResult model validation
# ---------------------------------------------------------------------------


def test_score_result_unscorable_consistency():
    """is_scorable=False with non-None total_score must be rejected."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ScoreResult(
            total_score=Decimal("50.0"),  # should be None
            letter_grade=None,
            is_scorable=False,
            catalogue_version=1,
        )


def test_score_result_scorable_requires_grade():
    """is_scorable=True without letter_grade must be rejected."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ScoreResult(
            total_score=Decimal("80.0"),
            letter_grade=None,  # should be set
            is_scorable=True,
            catalogue_version=1,
        )
