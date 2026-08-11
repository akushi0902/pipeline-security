"""Unit tests for matcher.py — pure reconcile logic.

Tests (all pass without database or network):
1.  Exact anchor match → true positive.
2.  Within-tolerance match (anchor ± tolerance) → true positive.
3.  Out-of-tolerance miss → false negative.
4.  Duplicate findings for same (control_id, line) collapse to one TP.
5.  Wrong control_id → no match (FN for gap, FP for finding).
6.  No findings → all gaps are false negatives.
7.  No gaps → all findings are false positives.
8.  NA fragment exclusion → gap inside fragment counted as na_gap not FN.
9.  NA gap detected by engine → recorded as na_mismatch.
10. Reproducibility: two calls with identical inputs produce identical digest.
11. Different inputs produce different digest.
12. Threshold evaluation — pass case.
13. Threshold evaluation — overall_min breach.
14. Threshold evaluation — per-format breach.
15. Threshold evaluation — max_false_positives breach.
16. Threshold evaluation — harness_error forces breach.
17. Precision and recall properties on FileReconciliation.
"""
from __future__ import annotations

import pytest

from pipelineshield.benchmark.ground_truth import (
    ExpectedStatus,
    PipelineFormat,
    SeededGap,
    Severity,
    UnassessableFragment,
)
from pipelineshield.benchmark.matcher import (
    BenchmarkRun,
    CategoryResult,
    FileReconciliation,
    FormatResult,
    compute_findings_digest,
    evaluate_thresholds,
    reconcile,
)
from pipelineshield.benchmark.runner import ValidatedFinding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _gap(
    file: str = "f.yml",
    control_id: str = "sh-001",
    line: int = 10,
    category: str = "secrets_hygiene",
    severity: str = "critical",
    status: str = "missing",
) -> SeededGap:
    return SeededGap(
        file=file,
        control_id=control_id,
        category=category,
        severity=Severity(severity),
        expected_status=ExpectedStatus(status),
        expected_anchor_line=line,
        rationale="test gap",
    )


def _finding(
    control_id: str = "sh-001",
    line: int = 10,
    rule_id: str = "sh-001/test",
) -> ValidatedFinding:
    return ValidatedFinding(
        control_id=control_id,
        start_line=line,
        anchor_text=f"line {line}",
        rule_id=rule_id,
    )


def _fragment(
    file: str = "f.yml",
    start: int = 20,
    end: int = 30,
) -> UnassessableFragment:
    return UnassessableFragment(
        file=file,
        reason="scripted block",
        line_start=start,
        line_end=end,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_exact_match_true_positive():
    gap = _gap(line=10)
    finding = _finding(line=10)
    recon = reconcile("f.yml", [finding], [gap], [])
    assert recon.tp == 1
    assert recon.fn == 0
    assert recon.fp == 0


def test_within_tolerance_positive():
    gap = _gap(line=10)
    finding = _finding(line=12)  # within ±2 default
    recon = reconcile("f.yml", [finding], [gap], [], tolerance=2)
    assert recon.tp == 1
    assert recon.fn == 0


def test_out_of_tolerance_miss():
    gap = _gap(line=10)
    finding = _finding(line=14)  # beyond ±2
    recon = reconcile("f.yml", [finding], [gap], [], tolerance=2)
    assert recon.fn == 1
    assert recon.fp == 1
    assert recon.tp == 0


def test_duplicate_findings_collapse_to_one_tp():
    gap = _gap(line=10)
    # Two findings for same control_id and line.
    findings = [_finding(line=10), _finding(line=10, rule_id="sh-001/dup")]
    recon = reconcile("f.yml", findings, [gap], [])
    assert recon.tp == 1
    assert recon.fp == 0  # duplicate collapsed — not treated as FP


def test_wrong_control_id_no_match():
    gap = _gap(control_id="sh-001", line=10)
    finding = _finding(control_id="as-001", line=10)
    recon = reconcile("f.yml", [finding], [gap], [])
    assert recon.fn == 1   # gap not detected
    assert recon.fp == 1   # finding unmatched
    assert recon.tp == 0


def test_no_findings_all_false_negatives():
    gaps = [_gap(control_id="sh-001", line=5), _gap(control_id="as-001", line=8)]
    recon = reconcile("f.yml", [], gaps, [])
    assert recon.fn == 2
    assert recon.tp == 0
    assert recon.fp == 0


def test_no_gaps_all_false_positives():
    findings = [_finding(line=5), _finding(control_id="as-001", line=8)]
    recon = reconcile("f.yml", findings, [], [])
    assert recon.fp == 2
    assert recon.tp == 0
    assert recon.fn == 0


def test_na_fragment_gap_excluded_from_fn():
    gap = _gap(line=25)  # inside fragment
    frag = _fragment(start=20, end=30)
    recon = reconcile("f.yml", [], [gap], [frag])
    assert len(recon.na_gaps) == 1
    assert recon.fn == 0
    assert recon.tp == 0


def test_na_gap_detected_by_engine_is_mismatch():
    gap = _gap(line=25)
    frag = _fragment(start=20, end=30)
    finding = _finding(line=25)
    recon = reconcile("f.yml", [finding], [gap], [frag])
    assert len(recon.na_mismatches) == 1
    assert recon.tp == 0
    assert recon.fn == 0


def test_reproducibility_identical_inputs_identical_digest():
    gaps = [_gap(line=10), _gap(control_id="as-001", line=15, category="artifact_signing")]
    findings = [_finding(line=10)]
    recon1 = reconcile("f.yml", findings, gaps, [])
    recon2 = reconcile("f.yml", findings, gaps, [])
    d1 = compute_findings_digest([recon1])
    d2 = compute_findings_digest([recon2])
    assert d1 == d2
    assert len(d1) == 64  # sha256 hex


def test_reproducibility_different_inputs_different_digest():
    gaps = [_gap(line=10)]
    findings_a = [_finding(line=10)]
    findings_b = [_finding(line=12)]
    recon_a = reconcile("f.yml", findings_a, gaps, [])
    recon_b = reconcile("f.yml", findings_b, gaps, [])
    d_a = compute_findings_digest([recon_a])
    d_b = compute_findings_digest([recon_b])
    assert d_a != d_b


def _make_benchmark_run(
    overall_rate: float | None = 0.85,
    fmt_name: str = "github_actions",
    fmt_rate: float | None = 0.85,
    fmt_fp: int = 2,
    overall_fp: int = 2,
    harness_errors: list | None = None,
) -> BenchmarkRun:
    fr = FormatResult(
        format=fmt_name,
        case_count=3,
        assessable_gaps=10,
        detected_gaps=int((fmt_rate or 0) * 10),
        false_negatives=10 - int((fmt_rate or 0) * 10),
        false_positives=fmt_fp,
        na_fragment_count=0,
        na_mismatch_count=0,
        detection_rate=fmt_rate,
        precision=None,
        recall=fmt_rate,
    )
    return BenchmarkRun(
        corpus_version="1.0.0",
        catalogue_version=1,
        git_commit_sha="abc1234",
        timestamp="2026-08-11T00:00:00+00:00",
        tolerance_lines=2,
        overall_detection_rate=overall_rate,
        overall_precision=None,
        overall_recall=overall_rate,
        overall_false_positives=overall_fp,
        per_format={fmt_name: fr},
        per_category={},
        files=[],
        findings_digest="a" * 64,
        harness_errors=harness_errors or [],
    )


def test_evaluate_thresholds_pass():
    run = _make_benchmark_run(overall_rate=0.90, fmt_rate=0.90, fmt_fp=3)
    thresholds = {
        "overall_min_detection": 0.80,
        "format_min_detection": {"github_actions": 0.80},
        "max_false_positives": 20,
    }
    breaches = evaluate_thresholds(run, thresholds)
    assert breaches == []


def test_evaluate_thresholds_overall_min_breach():
    run = _make_benchmark_run(overall_rate=0.75)
    thresholds = {"overall_min_detection": 0.80, "max_false_positives": 100}
    breaches = evaluate_thresholds(run, thresholds)
    assert any("overall detection_rate" in b for b in breaches)


def test_evaluate_thresholds_per_format_breach():
    run = _make_benchmark_run(overall_rate=0.85, fmt_rate=0.70)
    thresholds = {
        "overall_min_detection": 0.80,
        "format_min_detection": {"github_actions": 0.80},
        "max_false_positives": 100,
    }
    breaches = evaluate_thresholds(run, thresholds)
    assert any("github_actions" in b for b in breaches)


def test_evaluate_thresholds_max_fp_breach():
    run = _make_benchmark_run(overall_fp=25)
    thresholds = {"overall_min_detection": 0.80, "max_false_positives": 20}
    breaches = evaluate_thresholds(run, thresholds)
    assert any("false_positives" in b for b in breaches)


def test_evaluate_thresholds_harness_error_forces_breach():
    run = _make_benchmark_run(
        harness_errors=[{"file": "bad.yml", "error": "parse failed"}]
    )
    thresholds = {"overall_min_detection": 0.80, "max_false_positives": 100}
    breaches = evaluate_thresholds(run, thresholds)
    assert any("harness error" in b.lower() for b in breaches)


def test_precision_and_recall_properties():
    gap = _gap(line=10)
    findings = [_finding(line=10), _finding(control_id="as-001", line=20)]
    recon = reconcile("f.yml", findings, [gap], [])
    # TP=1, FN=0, FP=1
    assert recon.precision == pytest.approx(0.5)
    assert recon.recall == pytest.approx(1.0)
    assert recon.detection_rate == pytest.approx(1.0)


def test_detection_rate_none_when_no_assessable_gaps():
    recon = reconcile("f.yml", [], [], [])
    assert recon.detection_rate is None
    assert recon.recall is None
