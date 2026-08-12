"""Metrics computation for the benchmark harness.

Computes:
- Detection rate overall and per-format and per-control-category.
- Unanchored finding count (from suppression reports).
- Adjudication list (extra findings not matched to any seeded gap).
- Latency percentiles (p50, p95) over all timed iterations.
- Not-Assessable accounting per format.

Match rule (configurable tolerance):
  A seeded gap is *detected* when a validated finding shares its
  ``control_id`` AND its ``start_line`` falls within
  ``[expected_line - tolerance, expected_line + tolerance]``.
  ``tolerance`` defaults to 2 lines and is the documented parameter.

Zero-division handling:
  A corpus case with zero seeded gaps (e.g. hardened variant) must not
  divide by zero; detection rate is reported as ``None`` (not_applicable)
  and the case instead asserts zero violated outcomes.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from pipelineshield.catalogue.schemas import CatalogueSnapshot

from .manifest import CaseManifest, PipelineFormat, SeedGap
from .runner import CaseResult, ValidatedFinding

#: Default anchor-line tolerance (lines).  Documented in thresholds.yaml.
DEFAULT_TOLERANCE: int = 2


# ---------------------------------------------------------------------------
# Per-case metrics
# ---------------------------------------------------------------------------


@dataclass
class GapMatchResult:
    """Outcome of matching a single seeded gap."""

    gap: SeedGap
    detected: bool
    matching_finding: ValidatedFinding | None = None


@dataclass
class CaseMetrics:
    """Detection metrics for a single corpus case."""

    case_name: str
    format: PipelineFormat
    variant: str
    gap_results: list[GapMatchResult] = field(default_factory=list)
    adjudication_required: list[dict[str, Any]] = field(default_factory=list)
    case_error: str | None = None

    @property
    def total_gaps(self) -> int:
        return len(self.gap_results)

    @property
    def detected_gaps(self) -> int:
        return sum(1 for r in self.gap_results if r.detected)

    @property
    def detection_rate(self) -> float | None:
        """Detection rate as a fraction [0, 1] or None if no assessable gaps."""
        if self.total_gaps == 0:
            return None
        return self.detected_gaps / self.total_gaps

    @property
    def is_hardened(self) -> bool:
        return self.variant == "hardened"


# ---------------------------------------------------------------------------
# Aggregate metrics
# ---------------------------------------------------------------------------


@dataclass
class FormatMetrics:
    """Aggregated metrics for one pipeline format."""

    format: PipelineFormat
    total_gaps: int = 0
    detected_gaps: int = 0
    case_count: int = 0
    not_assessable_fragments: int = 0
    excluded_cases: int = 0  # cases where detection_rate is N/A (hardened, no gaps)

    @property
    def detection_rate(self) -> float | None:
        if self.total_gaps == 0:
            return None
        return self.detected_gaps / self.total_gaps

    @property
    def assessable_weight_ratio(self) -> float:
        """Fraction of lines that are assessable (1 - unassessable fraction)."""
        # Reported for informational purposes; not used for rate calculation.
        return 1.0  # placeholder updated by compute_metrics


@dataclass
class CategoryMetrics:
    """Aggregated metrics for one control category."""

    category_id: str
    category_name: str
    total_gaps: int = 0
    detected_gaps: int = 0

    @property
    def detection_rate(self) -> float | None:
        if self.total_gaps == 0:
            return None
        return self.detected_gaps / self.total_gaps


@dataclass
class LatencyMetrics:
    """Latency statistics over all timed iterations across all cases."""

    all_times_s: list[float] = field(default_factory=list)

    @property
    def p50_s(self) -> float | None:
        if not self.all_times_s:
            return None
        sorted_times = sorted(self.all_times_s)
        n = len(sorted_times)
        mid = n // 2
        if n % 2 == 0:
            return (sorted_times[mid - 1] + sorted_times[mid]) / 2
        return sorted_times[mid]

    @property
    def p95_s(self) -> float | None:
        if not self.all_times_s:
            return None
        sorted_times = sorted(self.all_times_s)
        n = len(sorted_times)
        idx = max(0, int(n * 0.95) - 1)
        return sorted_times[idx]


@dataclass
class BenchmarkMetrics:
    """Top-level aggregated benchmark metrics.

    Attributes:
        overall_detection_rate: Detected / total seeded gaps across all cases.
        per_format: Detection metrics broken down by pipeline format.
        per_category: Detection metrics broken down by control category.
        latency: Latency statistics over all timed iterations.
        unanchored_findings_count: Count of findings suppressed by anchor gate.
        adjudication_required: Extra findings not matched to a seeded gap.
        expected_unassessable: Gaps excluded because they are inside
            unassessable fragments.
        not_assessable_per_format: Per-format Not-Assessable fragment counts.
        case_metrics: Per-case detailed results.
        errors: Cases that failed with exceptions (case_error != None).
    """

    overall_detection_rate: float | None = None
    per_format: dict[PipelineFormat, FormatMetrics] = field(default_factory=dict)
    per_category: dict[str, CategoryMetrics] = field(default_factory=dict)
    latency: LatencyMetrics = field(default_factory=LatencyMetrics)
    unanchored_findings_count: int = 0
    adjudication_required: list[dict[str, Any]] = field(default_factory=list)
    expected_unassessable: int = 0
    not_assessable_per_format: dict[str, dict[str, Any]] = field(default_factory=dict)
    case_metrics: list[CaseMetrics] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------


def _gap_is_in_unassessable_fragment(gap: SeedGap, case_result: CaseResult) -> bool:
    """Return True if ``gap.expected_line`` falls inside any unassessable fragment."""
    for frag in case_result.coverage_report.unassessable_fragments:
        if frag.line_start <= gap.expected_line <= frag.line_end:
            return True
    return False


def _match_gap(
    gap: SeedGap,
    findings: list[ValidatedFinding],
    tolerance: int,
) -> GapMatchResult:
    """Match a seeded gap against validated findings using the documented rule.

    A gap is detected when a finding shares ``control_id`` and its
    ``start_line`` falls within ``[expected_line - tolerance, expected_line + tolerance]``.

    Args:
        gap: The seeded gap to match.
        findings: List of validated findings from the runner.
        tolerance: Anchor-line tolerance (default 2).

    Returns:
        ``GapMatchResult`` indicating whether the gap was detected.
    """
    lo = gap.expected_line - tolerance
    hi = gap.expected_line + tolerance
    for finding in findings:
        if (
            finding.control_id == gap.control_id
            and lo <= finding.start_line <= hi
        ):
            return GapMatchResult(gap=gap, detected=True, matching_finding=finding)
    return GapMatchResult(gap=gap, detected=False)


def _find_adjudication_required(
    manifest: CaseManifest,
    findings: list[ValidatedFinding],
    tolerance: int,
) -> list[dict[str, Any]]:
    """Return extra findings not matched to any seeded gap.

    These findings require human review — they are neither confirmed gaps nor
    confirmed false positives.
    """
    extra: list[dict[str, Any]] = []
    for finding in findings:
        matched = False
        for gap in manifest.seeded_gaps:
            lo = gap.expected_line - tolerance
            hi = gap.expected_line + tolerance
            if (
                finding.control_id == gap.control_id
                and lo <= finding.start_line <= hi
            ):
                matched = True
                break
        if not matched:
            extra.append(
                {
                    "control_id": finding.control_id,
                    "start_line": finding.start_line,
                    "anchor_text": finding.anchor_text,
                    "rule_id": finding.rule_id,
                    "detail": finding.detail,
                }
            )
    return extra


# ---------------------------------------------------------------------------
# Category lookup
# ---------------------------------------------------------------------------


def _build_category_map(
    catalogue: CatalogueSnapshot,
) -> dict[str, str]:
    """Return mapping of control_id → category_id."""
    return {
        ctrl.id: cat.id
        for cat in catalogue.categories
        for ctrl in cat.controls
    }


def _build_category_name_map(catalogue: CatalogueSnapshot) -> dict[str, str]:
    return {cat.id: cat.name for cat in catalogue.categories}


# ---------------------------------------------------------------------------
# Main computation
# ---------------------------------------------------------------------------


def compute_metrics(
    case_results: list[CaseResult],
    catalogue: CatalogueSnapshot,
    tolerance: int = DEFAULT_TOLERANCE,
) -> BenchmarkMetrics:
    """Compute aggregated benchmark metrics from case results.

    Args:
        case_results: List of ``CaseResult`` objects from the runner.
        catalogue: Active catalogue for category attribution.
        tolerance: Anchor-line match tolerance (lines).

    Returns:
        ``BenchmarkMetrics`` with all computed fields populated.
    """
    ctrl_to_cat = _build_category_map(catalogue)
    cat_name_map = _build_category_name_map(catalogue)

    # Initialise per-format metrics.
    fmt_metrics: dict[PipelineFormat, FormatMetrics] = {
        fmt: FormatMetrics(format=fmt) for fmt in PipelineFormat
    }
    # Initialise per-category metrics.
    cat_metrics: dict[str, CategoryMetrics] = {
        cat.id: CategoryMetrics(
            category_id=cat.id, category_name=cat.name
        )
        for cat in catalogue.categories
    }

    latency = LatencyMetrics()
    all_adjudication: list[dict[str, Any]] = []
    all_case_metrics: list[CaseMetrics] = []
    all_errors: list[dict[str, str]] = []
    total_unanchored = 0
    total_expected_unassessable = 0

    for result in case_results:
        fmt = result.manifest.format
        fmt_metrics[fmt].case_count += 1

        # Collect latency samples.
        latency.all_times_s.extend(result.iteration_times_s)

        # Unanchored findings.
        total_unanchored += len(result.suppression_report.unanchored_findings)

        if result.case_error:
            all_errors.append(
                {
                    "case_path": str(result.case_path),
                    "error": result.case_error,
                }
            )
            case_m = CaseMetrics(
                case_name=result.case_name,
                format=fmt,
                variant=result.manifest.variant,
                case_error=result.case_error,
            )
            all_case_metrics.append(case_m)
            fmt_metrics[fmt].excluded_cases += 1
            continue

        # Filter gaps inside unassessable fragments.
        assessable_gaps: list[SeedGap] = []
        for gap in result.manifest.seeded_gaps:
            if _gap_is_in_unassessable_fragment(gap, result):
                total_expected_unassessable += 1
            else:
                assessable_gaps.append(gap)

        # Match gaps.
        gap_results: list[GapMatchResult] = [
            _match_gap(gap, result.validated_findings, tolerance)
            for gap in assessable_gaps
        ]

        # Adjudication: extra findings not matched to any gap.
        extra = _find_adjudication_required(
            result.manifest, result.validated_findings, tolerance
        )
        all_adjudication.extend(extra)

        # Not-Assessable fragment count.
        fmt_metrics[fmt].not_assessable_fragments += len(
            result.coverage_report.unassessable_fragments
        )

        # Accumulate format-level totals.
        if assessable_gaps:
            detected = sum(1 for r in gap_results if r.detected)
            fmt_metrics[fmt].total_gaps += len(assessable_gaps)
            fmt_metrics[fmt].detected_gaps += detected
        else:
            fmt_metrics[fmt].excluded_cases += 1

        # Accumulate category-level totals.
        for gr in gap_results:
            cat_id = ctrl_to_cat.get(gr.gap.control_id)
            if cat_id and cat_id in cat_metrics:
                cat_metrics[cat_id].total_gaps += 1
                if gr.detected:
                    cat_metrics[cat_id].detected_gaps += 1

        case_m = CaseMetrics(
            case_name=result.case_name,
            format=fmt,
            variant=result.manifest.variant,
            gap_results=gap_results,
            adjudication_required=extra,
        )
        all_case_metrics.append(case_m)

    # Overall detection rate.
    total_gaps = sum(fm.total_gaps for fm in fmt_metrics.values())
    total_detected = sum(fm.detected_gaps for fm in fmt_metrics.values())
    overall_rate: float | None = (
        total_detected / total_gaps if total_gaps > 0 else None
    )

    # Not-Assessable per-format reporting.
    na_per_format: dict[str, dict[str, Any]] = {}
    for fmt, fm in fmt_metrics.items():
        # Compute average assessable weight ratio from case results
        format_cases = [
            r for r in case_results if r.manifest.format == fmt and not r.case_error
        ]
        avg_ratio = (
            sum(r.coverage_report.assessable_weight_ratio for r in format_cases)
            / len(format_cases)
            if format_cases
            else 1.0
        )
        na_per_format[fmt.value] = {
            "total_cases": fm.case_count,
            "unassessable_fragment_count": fm.not_assessable_fragments,
            "avg_assessable_weight_ratio": round(avg_ratio, 4),
            "excluded_cases_no_gaps": fm.excluded_cases,
            "detection_rate": fm.detection_rate,
        }

    return BenchmarkMetrics(
        overall_detection_rate=overall_rate,
        per_format=fmt_metrics,
        per_category=cat_metrics,
        latency=latency,
        unanchored_findings_count=total_unanchored,
        adjudication_required=all_adjudication,
        expected_unassessable=total_expected_unassessable,
        not_assessable_per_format=na_per_format,
        case_metrics=all_case_metrics,
        errors=all_errors,
    )
