"""Report renderers for the benchmark harness.

Produces two output formats:
1. Machine-readable JSON at a configured path for trend tracking.
2. Human-readable summary to stdout for release review.

JSON report schema (stable across versions):
  {
    "harness_version": str,
    "catalogue_version": int,
    "corpus_checksum": str,
    "run_timestamp": str (ISO-8601),
    "tolerance_lines": int,
    "aggregate": {
      "overall_detection_rate": float | null,
      "total_seeded_gaps": int,
      "detected_gaps": int,
      "unanchored_findings_count": int,
      "expected_unassessable": int,
      "latency_p50_s": float | null,
      "latency_p95_s": float | null
    },
    "per_format": { format_name: { ... } },
    "per_category": { category_id: { ... } },
    "not_assessable_per_format": { format_name: { ... } },
    "adjudication_required": [ { ... } ],
    "cases": [ { ... } ],
    "errors": [ { ... } ]
  }
"""
from __future__ import annotations

import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from pipelineshield.catalogue.schemas import CatalogueSnapshot

from .metrics import BenchmarkMetrics

#: Semantic version of the benchmark harness itself.
HARNESS_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------


def _rate_str(rate: float | None, decimals: int = 1) -> str:
    if rate is None:
        return "N/A"
    return f"{rate * 100:.{decimals}f}%"


def _build_json_payload(
    metrics: BenchmarkMetrics,
    catalogue: CatalogueSnapshot,
    catalogue_version: int,
    corpus_checksum: str,
    tolerance_lines: int,
    run_timestamp: str,
) -> dict[str, Any]:
    """Assemble the stable JSON document for trend tracking."""

    per_format_out: dict[str, Any] = {}
    for fmt, fm in metrics.per_format.items():
        per_format_out[fmt.value] = {
            "detection_rate": fm.detection_rate,
            "total_gaps": fm.total_gaps,
            "detected_gaps": fm.detected_gaps,
            "case_count": fm.case_count,
            "excluded_cases_no_gaps": fm.excluded_cases,
        }

    per_category_out: dict[str, Any] = {}
    for cat_id, cm in metrics.per_category.items():
        per_category_out[cat_id] = {
            "name": cm.category_name,
            "detection_rate": cm.detection_rate,
            "total_gaps": cm.total_gaps,
            "detected_gaps": cm.detected_gaps,
        }

    # Per-case results.
    cases_out: list[dict[str, Any]] = []
    for cm in metrics.case_metrics:
        if cm.case_error:
            cases_out.append(
                {
                    "case_name": cm.case_name,
                    "format": cm.format.value,
                    "variant": cm.variant,
                    "case_error": cm.case_error,
                }
            )
        else:
            cases_out.append(
                {
                    "case_name": cm.case_name,
                    "format": cm.format.value,
                    "variant": cm.variant,
                    "detection_rate": cm.detection_rate,
                    "total_gaps": cm.total_gaps,
                    "detected_gaps": cm.detected_gaps,
                    "gap_results": [
                        {
                            "control_id": gr.gap.control_id,
                            "expected_line": gr.gap.expected_line,
                            "severity": gr.gap.severity,
                            "detected": gr.detected,
                            "matched_line": (
                                gr.matching_finding.start_line
                                if gr.matching_finding
                                else None
                            ),
                        }
                        for gr in cm.gap_results
                    ],
                    "adjudication_required": cm.adjudication_required,
                }
            )

    return {
        "harness_version": HARNESS_VERSION,
        "catalogue_version": catalogue_version,
        "corpus_checksum": corpus_checksum,
        "run_timestamp": run_timestamp,
        "tolerance_lines": tolerance_lines,
        "aggregate": {
            "overall_detection_rate": metrics.overall_detection_rate,
            "total_seeded_gaps": sum(
                fm.total_gaps for fm in metrics.per_format.values()
            ),
            "detected_gaps": sum(
                fm.detected_gaps for fm in metrics.per_format.values()
            ),
            "unanchored_findings_count": metrics.unanchored_findings_count,
            "expected_unassessable": metrics.expected_unassessable,
            "latency_p50_s": metrics.latency.p50_s,
            "latency_p95_s": metrics.latency.p95_s,
        },
        "per_format": per_format_out,
        "per_category": per_category_out,
        "not_assessable_per_format": metrics.not_assessable_per_format,
        "adjudication_required": metrics.adjudication_required,
        "cases": cases_out,
        "errors": metrics.errors,
    }


def write_json_report(
    metrics: BenchmarkMetrics,
    catalogue: CatalogueSnapshot,
    catalogue_version: int,
    corpus_checksum: str,
    output_path: Path,
    tolerance_lines: int = 2,
    run_timestamp: str | None = None,
) -> dict[str, Any]:
    """Write the machine-readable JSON report to ``output_path``.

    Args:
        metrics: Computed benchmark metrics.
        catalogue: Active catalogue snapshot.
        catalogue_version: Integer version number of the active catalogue.
        corpus_checksum: SHA-256 hex digest of the corpus tree.
        output_path: Destination path for the JSON file.
        tolerance_lines: Documented tolerance used in this run.
        run_timestamp: ISO-8601 timestamp; defaults to UTC now if not provided.

    Returns:
        The assembled JSON-serialisable payload (for testing/inspection).
    """
    if run_timestamp is None:
        run_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = _build_json_payload(
        metrics=metrics,
        catalogue=catalogue,
        catalogue_version=catalogue_version,
        corpus_checksum=corpus_checksum,
        tolerance_lines=tolerance_lines,
        run_timestamp=run_timestamp,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    return payload


# ---------------------------------------------------------------------------
# Text summary
# ---------------------------------------------------------------------------


def write_text_summary(
    metrics: BenchmarkMetrics,
    catalogue_version: int,
    corpus_checksum: str,
    breached_thresholds: list[str],
    output: TextIO | None = None,
) -> None:
    """Write a human-readable summary to ``output`` (defaults to stdout).

    Args:
        metrics: Computed benchmark metrics.
        catalogue_version: Integer version of the active catalogue.
        corpus_checksum: Corpus SHA-256 hex digest (first 12 chars shown).
        breached_thresholds: List of threshold-breach description strings.
        output: Output stream; defaults to ``sys.stdout``.
    """
    out = output or sys.stdout

    def _w(line: str = "") -> None:
        out.write(line + "\n")

    _w("=" * 72)
    _w("PipelineShield Benchmark Harness — Seeded Corpus Detection Report")
    _w("=" * 72)
    _w(f"  Harness version  : {HARNESS_VERSION}")
    _w(f"  Catalogue version: {catalogue_version}")
    _w(f"  Corpus checksum  : {corpus_checksum[:12]}…")
    _w()

    _w("── Aggregate ─────────────────────────────────────────────────────────")
    _w(
        f"  Overall detection rate : "
        f"{_rate_str(metrics.overall_detection_rate)}"
    )
    total_gaps = sum(fm.total_gaps for fm in metrics.per_format.values())
    total_det = sum(fm.detected_gaps for fm in metrics.per_format.values())
    _w(f"  Seeded gaps            : {total_det} / {total_gaps} detected")
    _w(f"  Unanchored findings    : {metrics.unanchored_findings_count}")
    _w(f"  Expected unassessable  : {metrics.expected_unassessable}")
    _w(
        f"  Adjudication required  : "
        f"{len(metrics.adjudication_required)} extra finding(s)"
    )
    _w()

    _w("── Latency (deterministic path) ─────────────────────────────────────")
    p50 = metrics.latency.p50_s
    p95 = metrics.latency.p95_s
    _w(
        f"  p50 : "
        f"{f'{p50 * 1000:.1f} ms' if p50 is not None else 'N/A'}"
    )
    _w(
        f"  p95 : "
        f"{f'{p95 * 1000:.1f} ms' if p95 is not None else 'N/A'}"
    )
    _w()

    _w("── Detection by Format ───────────────────────────────────────────────")
    for fmt, fm in sorted(metrics.per_format.items(), key=lambda x: x[0].value):
        _w(
            f"  {fmt.value:<20} "
            f"{_rate_str(fm.detection_rate):>8}  "
            f"({fm.detected_gaps}/{fm.total_gaps} gaps,"
            f" {fm.case_count} cases)"
        )
    _w()

    _w("── Detection by Category ─────────────────────────────────────────────")
    for cat_id, cm in sorted(metrics.per_category.items()):
        if cm.total_gaps > 0:
            _w(
                f"  {cat_id:<30} "
                f"{_rate_str(cm.detection_rate):>8}  "
                f"({cm.detected_gaps}/{cm.total_gaps})"
            )
    _w()

    _w("── Not-Assessable Accounting per Format ──────────────────────────────")
    for fmt_name, na in sorted(metrics.not_assessable_per_format.items()):
        _w(f"  {fmt_name}:")
        _w(f"    Unassessable fragments : {na['unassessable_fragment_count']}")
        _w(f"    Avg assessable ratio   : {na['avg_assessable_weight_ratio']:.1%}")
        det_rate = na["detection_rate"]
        _w(
            f"    Detection rate         : {_rate_str(det_rate)}"
        )
    _w()

    if metrics.adjudication_required:
        _w("── Adjudication Required ─────────────────────────────────────────────")
        for item in metrics.adjudication_required:
            _w(
                f"  control={item['control_id']}  "
                f"line={item['start_line']}  "
                f"rule={item.get('rule_id', '?')}  "
                f"{item.get('detail', '')}"
            )
        _w()

    if metrics.errors:
        _w("── Errors ────────────────────────────────────────────────────────────")
        for err in metrics.errors:
            _w(f"  {err['case_path']}: {err['error']}")
        _w()

    if breached_thresholds:
        _w("── THRESHOLD BREACHES ────────────────────────────────────────────────")
        for breach in breached_thresholds:
            _w(f"  ✗ {breach}")
        _w()
        _w("RESULT: FAIL — quality gate breached (exit code 1)")
    else:
        _w("RESULT: PASS — all thresholds met")
    _w("=" * 72)


# ---------------------------------------------------------------------------
# Corpus checksum
# ---------------------------------------------------------------------------


def compute_corpus_checksum(corpus_root: Path) -> str:
    """Compute a deterministic SHA-256 digest of all corpus files.

    Visits files in sorted order so the digest is stable across platforms.
    """
    h = hashlib.sha256()
    for path in sorted(corpus_root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(corpus_root)
            h.update(str(rel).encode("utf-8"))
            h.update(path.read_bytes())
    return h.hexdigest()
