"""Pure finding-to-ground-truth reconciliation for the WO-046 detection gate.

reconcile() maps validated findings from the deterministic analysis path
against SeededGap and NegativeExpectation records from a GroundTruthManifest,
producing a FileReconciliation with:
  - true_positives   findings that match a declared seeded gap
  - false_negatives  declared gaps not covered by any finding
  - false_positives  findings produced for a control with no seeded gap
  - na_gaps          gaps inside unassessable fragments (excluded from rate)
  - na_mismatches    NA-expected gaps where the engine produced a finding

Match rule (documented parameter):
  A seeded gap is detected when a validated finding shares ``control_id`` AND
  its ``start_line`` falls within ``[expected_anchor_line - tolerance,
  expected_anchor_line + tolerance]``.  Duplicate findings for the same
  (control_id, line) are collapsed before matching so one gap cannot be
  counted as multiple true positives.

BenchmarkRun / FormatResult / CategoryResult are Pydantic v2 models for the
stable machine-readable schema consumed by the dashboard Trust panel.

Reproducibility:
  findings_digest is sha256 over the canonical sorted list of
  ``"<file>|<control_id>|<verdict>|<line>"`` strings.  Two runs over
  identical inputs must produce byte-identical digests — asserting this is the
  regression test for the zero-score-variance NFR.

No HTTP, no database, no network access.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from .ground_truth import NegativeExpectation, SeededGap, UnassessableFragment
from .runner import ValidatedFinding

#: Default anchor-line tolerance (±lines).
DEFAULT_TOLERANCE: int = 2


# ---------------------------------------------------------------------------
# Per-file reconciliation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchedPair:
    """A seeded gap matched by a validated finding (true positive)."""

    gap: SeededGap
    finding: ValidatedFinding


@dataclass
class FileReconciliation:
    """Detection outcome for one corpus file.

    Attributes:
        file:            Corpus-relative file path.
        true_positives:  Seeded gaps detected within tolerance.
        false_negatives: Seeded gaps NOT detected by any finding.
        false_positives: Findings that do not correspond to any seeded gap.
        na_gaps:         Gaps inside unassessable fragments (exempt from rate).
        na_mismatches:   NA-exempt gaps that the engine detected anyway
                         (coverage accuracy issue — neither TP nor FN).
    """

    file: str
    true_positives: list[MatchedPair] = field(default_factory=list)
    false_negatives: list[SeededGap] = field(default_factory=list)
    false_positives: list[ValidatedFinding] = field(default_factory=list)
    na_gaps: list[SeededGap] = field(default_factory=list)
    na_mismatches: list[SeededGap] = field(default_factory=list)
    harness_error: str | None = None

    @property
    def tp(self) -> int:
        return len(self.true_positives)

    @property
    def fn(self) -> int:
        return len(self.false_negatives)

    @property
    def fp(self) -> int:
        return len(self.false_positives)

    @property
    def detection_rate(self) -> float | None:
        """TP / (TP + FN); None when there are no assessable gaps."""
        total = self.tp + self.fn
        return self.tp / total if total > 0 else None

    @property
    def precision(self) -> float | None:
        """TP / (TP + FP); None when the engine produced zero findings."""
        total = self.tp + self.fp
        return self.tp / total if total > 0 else None

    @property
    def recall(self) -> float | None:
        """Alias for detection_rate (TP / (TP + FN))."""
        return self.detection_rate


# ---------------------------------------------------------------------------
# Core reconcile function
# ---------------------------------------------------------------------------


def _gap_in_unassessable(
    gap: SeededGap,
    fragments: list[UnassessableFragment],
) -> bool:
    for frag in fragments:
        if frag.line_start <= gap.expected_anchor_line <= frag.line_end:
            return True
    return False


def _deduplicate_findings(
    findings: list[ValidatedFinding],
) -> list[ValidatedFinding]:
    """Collapse multiple findings for the same (control_id, line) to one."""
    seen: set[tuple[str, int]] = set()
    deduped: list[ValidatedFinding] = []
    for f in findings:
        key = (f.control_id, f.start_line)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def reconcile(
    file: str,
    findings: list[ValidatedFinding],
    seeded_gaps: list[SeededGap],
    unassessable_fragments: list[UnassessableFragment],
    tolerance: int = DEFAULT_TOLERANCE,
) -> FileReconciliation:
    """Reconcile validated findings against declared ground truth for one file.

    Args:
        file:                  Corpus-relative file path (for labelling).
        findings:              Validated findings from the deterministic runner.
        seeded_gaps:           Declared gaps for this file from the manifest.
        unassessable_fragments: Regions excluded from the detection denominator.
        tolerance:             ±lines window for anchor matching.

    Returns:
        ``FileReconciliation`` with TP/FN/FP classification.
    """
    deduped = _deduplicate_findings(findings)

    # Split gaps into assessable and NA.
    assessable: list[SeededGap] = []
    na_gaps: list[SeededGap] = []
    for gap in seeded_gaps:
        if _gap_in_unassessable(gap, unassessable_fragments):
            na_gaps.append(gap)
        else:
            assessable.append(gap)

    # Track which findings have been matched.
    matched_finding_indices: set[int] = set()

    true_positives: list[MatchedPair] = []
    false_negatives: list[SeededGap] = []

    for gap in assessable:
        lo = gap.expected_anchor_line - tolerance
        hi = gap.expected_anchor_line + tolerance
        hit: ValidatedFinding | None = None
        for idx, f in enumerate(deduped):
            if f.control_id == gap.control_id and lo <= f.start_line <= hi:
                hit = f
                matched_finding_indices.add(idx)
                break
        if hit is not None:
            true_positives.append(MatchedPair(gap=gap, finding=hit))
        else:
            false_negatives.append(gap)

    # Also check NA gaps: if the engine found one, record it as a mismatch.
    na_mismatches: list[SeededGap] = []
    for gap in na_gaps:
        lo = gap.expected_anchor_line - tolerance
        hi = gap.expected_anchor_line + tolerance
        for idx, f in enumerate(deduped):
            if f.control_id == gap.control_id and lo <= f.start_line <= hi:
                matched_finding_indices.add(idx)
                na_mismatches.append(gap)
                break

    # Unmatched findings are false positives.
    false_positives = [
        f for idx, f in enumerate(deduped)
        if idx not in matched_finding_indices
    ]

    return FileReconciliation(
        file=file,
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
        na_gaps=na_gaps,
        na_mismatches=na_mismatches,
    )


# ---------------------------------------------------------------------------
# Reproducibility digest
# ---------------------------------------------------------------------------


def compute_findings_digest(reconciliations: list[FileReconciliation]) -> str:
    """Compute a stable sha256 over all reconciliation verdicts.

    The digest is derived from a sorted canonical list of
    ``"<file>|<control_id>|<verdict>|<line>"`` strings so that two runs
    over identical inputs produce byte-identical digests.

    Verdicts: "tp", "fn", "fp", "na_gap", "na_mismatch".
    """
    entries: list[str] = []

    for r in reconciliations:
        for pair in r.true_positives:
            entries.append(
                f"{r.file}|{pair.gap.control_id}|tp|{pair.finding.start_line}"
            )
        for gap in r.false_negatives:
            entries.append(
                f"{r.file}|{gap.control_id}|fn|{gap.expected_anchor_line}"
            )
        for f in r.false_positives:
            entries.append(
                f"{r.file}|{f.control_id}|fp|{f.start_line}"
            )
        for gap in r.na_gaps:
            entries.append(
                f"{r.file}|{gap.control_id}|na_gap|{gap.expected_anchor_line}"
            )
        for gap in r.na_mismatches:
            entries.append(
                f"{r.file}|{gap.control_id}|na_mismatch|{gap.expected_anchor_line}"
            )

    payload = "\n".join(sorted(entries)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Pydantic v2 results schema
# ---------------------------------------------------------------------------


class FormatResult(BaseModel):
    """Detection metrics for one pipeline format."""

    format: str
    case_count: int
    assessable_gaps: int
    detected_gaps: int
    false_negatives: int
    false_positives: int
    na_fragment_count: int
    na_mismatch_count: int
    detection_rate: float | None = None
    precision: float | None = None
    recall: float | None = None

    model_config = {"frozen": True}


class CategoryResult(BaseModel):
    """Detection metrics for one control category."""

    category_id: str
    total_gaps: int
    detected_gaps: int
    false_positives: int
    detection_rate: float | None = None

    model_config = {"frozen": True}


class FileDetail(BaseModel):
    """Per-file reconciliation summary for the results artefact."""

    file: str
    format: str
    variant: str
    true_positives: int
    false_negatives: int
    false_positives: int
    na_gaps: int
    harness_error: str | None = None
    detection_rate: float | None = None
    false_negative_controls: list[str] = Field(default_factory=list)

    model_config = {"frozen": True}


class BenchmarkRun(BaseModel):
    """Complete machine-readable benchmark run result.

    Consumed by the dashboard Trust panel via GET /api/v1/benchmark/latest.

    Fields:
        corpus_version:          Version string from the manifest.
        catalogue_version:       Integer version of the active catalogue.
        git_commit_sha:          Git HEAD sha at run time (or "unknown").
        timestamp:               ISO-8601 UTC run timestamp.
        tolerance_lines:         ±line tolerance used for anchor matching.
        overall_detection_rate:  TP / (TP + FN) across all assessable gaps.
        overall_precision:       TP / (TP + FP).
        overall_recall:          Alias for overall_detection_rate.
        overall_false_positives: Total FP count.
        per_format:              Detection metrics per format.
        per_category:            Detection metrics per control category.
        findings_digest:         sha256 reproducibility digest.
        harness_errors:          Files that failed with exceptions.
        jenkins_separately_reported: Always True — Jenkins is never folded
                                     into the aggregate headline.
    """

    corpus_version: str
    catalogue_version: int
    git_commit_sha: str
    timestamp: str
    tolerance_lines: int
    overall_detection_rate: float | None = None
    overall_precision: float | None = None
    overall_recall: float | None = None
    overall_false_positives: int = 0
    per_format: dict[str, FormatResult] = Field(default_factory=dict)
    per_category: dict[str, CategoryResult] = Field(default_factory=dict)
    files: list[FileDetail] = Field(default_factory=list)
    findings_digest: str = ""
    harness_errors: list[dict[str, str]] = Field(default_factory=list)
    jenkins_separately_reported: bool = True

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Threshold evaluation
# ---------------------------------------------------------------------------


def evaluate_thresholds(
    run: BenchmarkRun,
    thresholds: dict[str, Any],
) -> list[str]:
    """Return human-readable breach descriptions (empty list = all pass).

    Args:
        run:        Completed benchmark run.
        thresholds: Loaded threshold dict (from thresholds.yaml or overrides).

    Returns:
        List of breach descriptions; non-empty triggers exit code 1.
    """
    breaches: list[str] = []

    # Harness errors count as breaches — one broken file cannot be silenced.
    if run.harness_errors:
        breaches.append(
            f"{len(run.harness_errors)} file(s) produced harness errors: "
            + ", ".join(e.get("file", "?") for e in run.harness_errors)
        )

    # Overall detection rate.
    overall_min = float(thresholds.get("overall_min_detection", 0.80))
    if run.overall_detection_rate is not None and run.overall_detection_rate < overall_min:
        breaches.append(
            f"overall detection_rate={run.overall_detection_rate:.1%} "
            f"< threshold {overall_min:.0%}"
        )

    # Per-format detection rates.
    fmt_thresholds: dict[str, float] = thresholds.get("format_min_detection", {})
    for fmt_name, fmt_result in run.per_format.items():
        fmt_min = float(fmt_thresholds.get(fmt_name, 0.80))
        if (
            fmt_result.detection_rate is not None
            and fmt_result.assessable_gaps > 0
            and fmt_result.detection_rate < fmt_min
        ):
            breaches.append(
                f"{fmt_name} detection_rate={fmt_result.detection_rate:.1%} "
                f"< threshold {fmt_min:.0%}"
            )

    # False positive ceiling.
    max_fp = int(thresholds.get("max_false_positives", 20))
    if run.overall_false_positives > max_fp:
        breaches.append(
            f"overall false_positives={run.overall_false_positives} "
            f"> max allowed {max_fp}"
        )

    return breaches
