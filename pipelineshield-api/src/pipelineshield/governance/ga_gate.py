"""GA Gate Service — ratified O6 thresholds and pure evaluation functions.

The threshold constants are verbatim from the O6 ratification document.
They MUST NOT be re-derived, rounded, or altered.  A unit test asserts
each constant matches the documented ratified value.

All evaluation functions are pure — no database calls, no I/O.  They
accept pre-aggregated metric values and return ThresholdResult objects
that the GA gate endpoint assembles into a GaGateResponse.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Ratified O6 threshold constants — VERBATIM, do not modify
# ---------------------------------------------------------------------------

WORKSPACES_SIGNED_OFF_PCT: int = 100
TARGET_WORKSPACE_COUNT: int = 5
PERSONAS_COVERED_TARGET: int = 5
ACCURACY_RATING_PCT_MIN: int = 80
DEFINITIONS_ANALYSED_MIN: int = 40
REANALYSIS_RATE_PCT_MIN: int = 50
MEDIAN_SCORE_IMPROVEMENT_MIN: int = 15
LATENCY_P95_S_MAX: int = 30
LATENCY_P50_S_MAX: int = 12
MAX_FABRICATED_FINDINGS: int = 0
MAX_SECRET_EXPOSURE_INCIDENTS: int = 0
MAX_AUTHZ_VIOLATIONS: int = 0
MAX_PURGE_SLA_BREACHES: int = 0


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThresholdResult:
    """Evaluated result for a single GA gate threshold."""

    key: str
    label: str
    target: Any
    comparator: str
    current: Any
    status: str  # "pass" | "fail" | "insufficient_data"
    source: str


@dataclass(frozen=True)
class GaGateEvaluation:
    """Aggregate GA gate evaluation result."""

    overall_status: str  # "pass" | "fail"
    evaluated_at: datetime
    thresholds: list[ThresholdResult]
    failing: list[str]


# ---------------------------------------------------------------------------
# Pure threshold evaluators
# ---------------------------------------------------------------------------


def _eval_gte(key: str, label: str, target: int | float, current: int | float | None, source: str) -> ThresholdResult:
    """Pass when current >= target.  Insufficient data when current is None."""
    if current is None:
        return ThresholdResult(
            key=key, label=label, target=target, comparator=">=",
            current=None, status="insufficient_data", source=source,
        )
    status = "pass" if current >= target else "fail"
    return ThresholdResult(
        key=key, label=label, target=target, comparator=">=",
        current=current, status=status, source=source,
    )


def _eval_lte(key: str, label: str, target: int | float, current: int | float | None, source: str) -> ThresholdResult:
    """Pass when current <= target.  Insufficient data when current is None."""
    if current is None:
        return ThresholdResult(
            key=key, label=label, target=target, comparator="<=",
            current=None, status="insufficient_data", source=source,
        )
    status = "pass" if current <= target else "fail"
    return ThresholdResult(
        key=key, label=label, target=target, comparator="<=",
        current=current, status=status, source=source,
    )


def _eval_eq(key: str, label: str, target: int, current: int | None, source: str) -> ThresholdResult:
    """Pass when current == target (used for zero-tolerance counters)."""
    if current is None:
        return ThresholdResult(
            key=key, label=label, target=target, comparator="==",
            current=None, status="insufficient_data", source=source,
        )
    status = "pass" if current == target else "fail"
    return ThresholdResult(
        key=key, label=label, target=target, comparator="==",
        current=current, status=status, source=source,
    )


# ---------------------------------------------------------------------------
# Aggregate gate evaluator
# ---------------------------------------------------------------------------


def evaluate_ga_gate(
    *,
    workspaces_signed_off_pct: int | None,
    accuracy_rating_pct: int | None,
    definitions_analysed: int | None,
    reanalysis_rate_pct: int | None,
    median_score_improvement: int | None,
    latency_p95_s: float | None,
    latency_p50_s: float | None,
    fabricated_findings: int | None,
    secret_exposure_incidents: int | None,
    authz_violations: int | None,
    purge_sla_breaches: int | None,
) -> GaGateEvaluation:
    """Evaluate every ratified O6 threshold and return the aggregate result.

    All inputs are pre-aggregated metric values from the repositories.
    None signals that a measurement source is unavailable — those thresholds
    are marked insufficient_data and contribute to an overall fail.
    """
    results: list[ThresholdResult] = [
        _eval_gte(
            "workspaces_signed_off",
            "Pilot Workspaces Signed Off (%)",
            WORKSPACES_SIGNED_OFF_PCT,
            workspaces_signed_off_pct,
            "pilot_signoff table — latest decision per workspace",
        ),
        _eval_gte(
            "accuracy_rating_pct",
            "Accuracy & Actionability Rating ≥ 80%",
            ACCURACY_RATING_PCT_MIN,
            accuracy_rating_pct,
            "pilot_signoff.accuracy_actionability_rating aggregation",
        ),
        _eval_gte(
            "definitions_analysed",
            "Distinct Definitions Analysed",
            DEFINITIONS_ANALYSED_MIN,
            definitions_analysed,
            "analysis JOIN pipeline_definition WHERE is_sample = false",
        ),
        _eval_gte(
            "reanalysis_rate_pct",
            "Re-analysis Rate (%)",
            REANALYSIS_RATE_PCT_MIN,
            reanalysis_rate_pct,
            "workspaces with ≥ 2 analyses / total non-sample workspaces",
        ),
        _eval_gte(
            "median_score_improvement",
            "Median Score Improvement (points)",
            MEDIAN_SCORE_IMPROVEMENT_MIN,
            median_score_improvement,
            "median(latest_score - first_score) per workspace with ≥ 2 analyses",
        ),
        _eval_lte(
            "latency_p95_seconds",
            "Analysis Latency P95 (s)",
            LATENCY_P95_S_MAX,
            latency_p95_s,
            "analysis.duration_ms percentile — p95",
        ),
        _eval_lte(
            "latency_p50_seconds",
            "Analysis Latency P50 (s)",
            LATENCY_P50_S_MAX,
            latency_p50_s,
            "analysis.duration_ms percentile — p50",
        ),
        _eval_eq(
            "fabricated_findings",
            "Fabricated Findings (zero-tolerance)",
            MAX_FABRICATED_FINDINGS,
            fabricated_findings,
            "benchmark harness fabricated-findings counter",
        ),
        _eval_eq(
            "secret_exposure_incidents",
            "Secret Exposure Incidents (zero-tolerance)",
            MAX_SECRET_EXPOSURE_INCIDENTS,
            secret_exposure_incidents,
            "WO-040 leakage suite result",
        ),
        _eval_eq(
            "authz_violations",
            "Authorization Violations (zero-tolerance)",
            MAX_AUTHZ_VIOLATIONS,
            authz_violations,
            "audit_event WHERE action = 'authz.denied'",
        ),
        _eval_eq(
            "purge_sla_breaches",
            "Purge SLA Breaches (zero-tolerance)",
            MAX_PURGE_SLA_BREACHES,
            purge_sla_breaches,
            "purge_receipt reconciliation report",
        ),
    ]

    failing = [
        r.key for r in results if r.status in ("fail", "insufficient_data")
    ]
    overall_status = "pass" if not failing else "fail"

    return GaGateEvaluation(
        overall_status=overall_status,
        evaluated_at=datetime.now(timezone.utc),
        thresholds=results,
        failing=failing,
    )
