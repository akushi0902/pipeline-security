"""Unit tests for ga_gate.py — threshold constants and pure evaluation functions.

Tests (all pass without database or network):
1.  Constant values match the documented O6 ratified values verbatim.
2.  _eval_gte — pass at threshold, fail below, insufficient when None.
3.  _eval_lte — pass at threshold, fail above, insufficient when None.
4.  _eval_eq  — pass equals zero, fail non-zero, insufficient when None.
5.  evaluate_ga_gate — all-pass corpus.
6.  evaluate_ga_gate — single failing threshold yields overall fail.
7.  evaluate_ga_gate — zero-tolerance counter non-zero yields fail.
8.  evaluate_ga_gate — None input yields insufficient_data and overall fail.
9.  Aggregate pass requires ALL thresholds to pass (table-driven).
10. Median improvement boundary: exactly 15 passes, 14 fails.
11. Latency boundary: exactly 30 s p95 passes, 30.001 fails.
12. Workspaces signed-off at 100% passes, 99% fails.
13. Failing list enumerates only the failing threshold keys.
"""
from __future__ import annotations

import pytest

from pipelineshield.governance.ga_gate import (
    ACCURACY_RATING_PCT_MIN,
    DEFINITIONS_ANALYSED_MIN,
    LATENCY_P50_S_MAX,
    LATENCY_P95_S_MAX,
    MAX_AUTHZ_VIOLATIONS,
    MAX_FABRICATED_FINDINGS,
    MAX_PURGE_SLA_BREACHES,
    MAX_SECRET_EXPOSURE_INCIDENTS,
    MEDIAN_SCORE_IMPROVEMENT_MIN,
    PERSONAS_COVERED_TARGET,
    REANALYSIS_RATE_PCT_MIN,
    TARGET_WORKSPACE_COUNT,
    WORKSPACES_SIGNED_OFF_PCT,
    _eval_eq,
    _eval_gte,
    _eval_lte,
    evaluate_ga_gate,
)


# ---------------------------------------------------------------------------
# 1. Constants match ratified O6 values
# ---------------------------------------------------------------------------

def test_constants_match_ratified_values():
    assert WORKSPACES_SIGNED_OFF_PCT == 100
    assert TARGET_WORKSPACE_COUNT == 5
    assert PERSONAS_COVERED_TARGET == 5
    assert ACCURACY_RATING_PCT_MIN == 80
    assert DEFINITIONS_ANALYSED_MIN == 40
    assert REANALYSIS_RATE_PCT_MIN == 50
    assert MEDIAN_SCORE_IMPROVEMENT_MIN == 15
    assert LATENCY_P95_S_MAX == 30
    assert LATENCY_P50_S_MAX == 12
    assert MAX_FABRICATED_FINDINGS == 0
    assert MAX_SECRET_EXPOSURE_INCIDENTS == 0
    assert MAX_AUTHZ_VIOLATIONS == 0
    assert MAX_PURGE_SLA_BREACHES == 0


# ---------------------------------------------------------------------------
# 2-4. Atomic evaluators
# ---------------------------------------------------------------------------

def test_eval_gte_pass_at_threshold():
    r = _eval_gte("k", "L", 80, 80, "src")
    assert r.status == "pass"


def test_eval_gte_fail_below_threshold():
    r = _eval_gte("k", "L", 80, 79, "src")
    assert r.status == "fail"


def test_eval_gte_pass_above_threshold():
    r = _eval_gte("k", "L", 80, 100, "src")
    assert r.status == "pass"


def test_eval_gte_none_is_insufficient():
    r = _eval_gte("k", "L", 80, None, "src")
    assert r.status == "insufficient_data"
    assert r.current is None


def test_eval_lte_pass_at_threshold():
    r = _eval_lte("k", "L", 30, 30.0, "src")
    assert r.status == "pass"


def test_eval_lte_fail_above_threshold():
    r = _eval_lte("k", "L", 30, 30.001, "src")
    assert r.status == "fail"


def test_eval_lte_none_is_insufficient():
    r = _eval_lte("k", "L", 30, None, "src")
    assert r.status == "insufficient_data"


def test_eval_eq_pass_zero():
    r = _eval_eq("k", "L", 0, 0, "src")
    assert r.status == "pass"


def test_eval_eq_fail_nonzero():
    r = _eval_eq("k", "L", 0, 1, "src")
    assert r.status == "fail"


def test_eval_eq_none_is_insufficient():
    r = _eval_eq("k", "L", 0, None, "src")
    assert r.status == "insufficient_data"


# ---------------------------------------------------------------------------
# 5. All-pass corpus
# ---------------------------------------------------------------------------

def _make_full_pass_kwargs():
    return dict(
        workspaces_signed_off_pct=100,
        accuracy_rating_pct=80,
        definitions_analysed=40,
        reanalysis_rate_pct=50,
        median_score_improvement=15,
        latency_p95_s=30.0,
        latency_p50_s=12.0,
        fabricated_findings=0,
        secret_exposure_incidents=0,
        authz_violations=0,
        purge_sla_breaches=0,
    )


def test_evaluate_ga_gate_all_pass():
    result = evaluate_ga_gate(**_make_full_pass_kwargs())
    assert result.overall_status == "pass"
    assert result.failing == []
    for t in result.thresholds:
        assert t.status == "pass", f"Expected pass for {t.key}, got {t.status}"


# ---------------------------------------------------------------------------
# 6. Single failing threshold
# ---------------------------------------------------------------------------

def test_evaluate_ga_gate_single_failing_threshold():
    kwargs = _make_full_pass_kwargs()
    kwargs["definitions_analysed"] = 39  # one below threshold
    result = evaluate_ga_gate(**kwargs)
    assert result.overall_status == "fail"
    assert "definitions_analysed" in result.failing


# ---------------------------------------------------------------------------
# 7. Zero-tolerance counter non-zero
# ---------------------------------------------------------------------------

def test_evaluate_ga_gate_zero_tolerance_authz_violation():
    kwargs = _make_full_pass_kwargs()
    kwargs["authz_violations"] = 1
    result = evaluate_ga_gate(**kwargs)
    assert result.overall_status == "fail"
    assert "authz_violations" in result.failing


def test_evaluate_ga_gate_zero_tolerance_purge_sla():
    kwargs = _make_full_pass_kwargs()
    kwargs["purge_sla_breaches"] = 1
    result = evaluate_ga_gate(**kwargs)
    assert result.overall_status == "fail"
    assert "purge_sla_breaches" in result.failing


# ---------------------------------------------------------------------------
# 8. None input → insufficient_data → overall fail
# ---------------------------------------------------------------------------

def test_evaluate_ga_gate_none_input_is_insufficient_data():
    kwargs = _make_full_pass_kwargs()
    kwargs["latency_p95_s"] = None
    result = evaluate_ga_gate(**kwargs)
    assert result.overall_status == "fail"
    latency_t = next(t for t in result.thresholds if t.key == "latency_p95_seconds")
    assert latency_t.status == "insufficient_data"
    assert "latency_p95_seconds" in result.failing


# ---------------------------------------------------------------------------
# 9. Table-driven: one failing threshold per metric always fails overall
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,bad_value", [
    ("workspaces_signed_off_pct", 99),
    ("accuracy_rating_pct", 79),
    ("definitions_analysed", 39),
    ("reanalysis_rate_pct", 49),
    ("median_score_improvement", 14),
    ("fabricated_findings", 1),
    ("secret_exposure_incidents", 1),
    ("authz_violations", 1),
    ("purge_sla_breaches", 1),
])
def test_single_failing_metric_fails_gate(field, bad_value):
    kwargs = _make_full_pass_kwargs()
    kwargs[field] = bad_value
    result = evaluate_ga_gate(**kwargs)
    assert result.overall_status == "fail"


# ---------------------------------------------------------------------------
# 10. Median improvement boundary: 15 passes, 14 fails
# ---------------------------------------------------------------------------

def test_median_score_improvement_boundary_pass():
    kwargs = _make_full_pass_kwargs()
    kwargs["median_score_improvement"] = 15
    result = evaluate_ga_gate(**kwargs)
    t = next(t for t in result.thresholds if t.key == "median_score_improvement")
    assert t.status == "pass"


def test_median_score_improvement_boundary_fail():
    kwargs = _make_full_pass_kwargs()
    kwargs["median_score_improvement"] = 14
    result = evaluate_ga_gate(**kwargs)
    t = next(t for t in result.thresholds if t.key == "median_score_improvement")
    assert t.status == "fail"


# ---------------------------------------------------------------------------
# 11. Latency boundary
# ---------------------------------------------------------------------------

def test_latency_p95_boundary_pass():
    kwargs = _make_full_pass_kwargs()
    kwargs["latency_p95_s"] = 30.0
    result = evaluate_ga_gate(**kwargs)
    t = next(t for t in result.thresholds if t.key == "latency_p95_seconds")
    assert t.status == "pass"


def test_latency_p95_boundary_fail():
    kwargs = _make_full_pass_kwargs()
    kwargs["latency_p95_s"] = 30.001
    result = evaluate_ga_gate(**kwargs)
    t = next(t for t in result.thresholds if t.key == "latency_p95_seconds")
    assert t.status == "fail"


# ---------------------------------------------------------------------------
# 12. Workspaces signed-off boundary
# ---------------------------------------------------------------------------

def test_workspaces_signed_off_100_passes():
    kwargs = _make_full_pass_kwargs()
    kwargs["workspaces_signed_off_pct"] = 100
    result = evaluate_ga_gate(**kwargs)
    t = next(t for t in result.thresholds if t.key == "workspaces_signed_off")
    assert t.status == "pass"


def test_workspaces_signed_off_99_fails():
    kwargs = _make_full_pass_kwargs()
    kwargs["workspaces_signed_off_pct"] = 99
    result = evaluate_ga_gate(**kwargs)
    t = next(t for t in result.thresholds if t.key == "workspaces_signed_off")
    assert t.status == "fail"


# ---------------------------------------------------------------------------
# 13. Failing list enumerates only failing keys
# ---------------------------------------------------------------------------

def test_failing_list_enumerates_only_failing_keys():
    kwargs = _make_full_pass_kwargs()
    kwargs["authz_violations"] = 2
    kwargs["purge_sla_breaches"] = 3
    result = evaluate_ga_gate(**kwargs)
    assert set(result.failing) == {"authz_violations", "purge_sla_breaches"}
