"""CLI entry point for the benchmark harness.

Usage::

    python -m pipelineshield.benchmark [OPTIONS]

Exit codes:
    0  All thresholds met.
    1  One or more quality-gate thresholds breached.
    2  Harness fault (invalid manifest, empty corpus, uncaught exception).

Options are documented in ``--help``.  Thresholds can be overridden on the
command line; defaults are loaded from ``thresholds.yaml`` alongside this
module.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

import yaml

from pipelineshield.catalogue.schemas import CatalogueSnapshot

from .manifest import ManifestValidationError, load_corpus_manifests
from .metrics import BenchmarkMetrics, compute_metrics
from .report import HARNESS_VERSION, compute_corpus_checksum, write_json_report, write_text_summary
from .runner import RunnerError, run_case

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent
_DEFAULT_CORPUS_ROOT = _THIS_DIR / "corpus"
_DEFAULT_THRESHOLDS_PATH = _THIS_DIR / "thresholds.yaml"
_DEFAULT_CATALOGUE_PATH = (
    Path(__file__).resolve().parents[4]
    / "tests"
    / "fixtures"
    / "catalogue_v1.json"
)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_GATE_BREACH = 1
EXIT_HARNESS_FAULT = 2


# ---------------------------------------------------------------------------
# Threshold loading
# ---------------------------------------------------------------------------


def load_thresholds(path: Path) -> dict[str, Any]:
    """Load and return the threshold configuration from a YAML file."""
    if not path.exists():
        print(f"ERROR: thresholds file not found: {path}", file=sys.stderr)
        sys.exit(EXIT_HARNESS_FAULT)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"ERROR: could not parse thresholds file: {exc}", file=sys.stderr)
        sys.exit(EXIT_HARNESS_FAULT)
    return data or {}


# ---------------------------------------------------------------------------
# Catalogue loading
# ---------------------------------------------------------------------------


def load_catalogue(path: Path) -> CatalogueSnapshot:
    """Load and validate the catalogue snapshot from a JSON file."""
    if not path.exists():
        print(
            f"ERROR: catalogue file not found: {path}\n"
            "Provide --catalogue-path pointing to a valid catalogue_v1.json.",
            file=sys.stderr,
        )
        sys.exit(EXIT_HARNESS_FAULT)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return CatalogueSnapshot.model_validate(raw)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: could not load catalogue: {exc}", file=sys.stderr)
        sys.exit(EXIT_HARNESS_FAULT)


# ---------------------------------------------------------------------------
# Threshold evaluation
# ---------------------------------------------------------------------------


def evaluate_thresholds(
    metrics: BenchmarkMetrics,
    thresholds: dict[str, Any],
) -> list[str]:
    """Return a list of breached threshold descriptions (empty if all pass).

    Args:
        metrics: Computed benchmark metrics.
        thresholds: Loaded threshold configuration dict.

    Returns:
        List of human-readable breach descriptions.
    """
    from .manifest import PipelineFormat

    breaches: list[str] = []

    # Error cases count as breaches.
    if metrics.errors:
        breaches.append(
            f"{len(metrics.errors)} case(s) failed with errors: "
            + ", ".join(e["case_path"] for e in metrics.errors)
        )

    # Zero-fabrication gate.
    max_unanchored = int(thresholds.get("max_unanchored_findings", 0))
    if metrics.unanchored_findings_count > max_unanchored:
        breaches.append(
            f"unanchored_findings={metrics.unanchored_findings_count} "
            f"> max allowed {max_unanchored} "
            "(zero-fabrication gate violated)"
        )

    # Overall detection rate.
    overall_min = float(thresholds.get("overall_min_detection", 0.80))
    if (
        metrics.overall_detection_rate is not None
        and metrics.overall_detection_rate < overall_min
    ):
        breaches.append(
            f"overall_detection_rate={metrics.overall_detection_rate:.1%} "
            f"< threshold {overall_min:.0%}"
        )

    # Per-format detection rates.
    fmt_thresholds: dict[str, float] = thresholds.get("format_min_detection", {})
    for fmt in PipelineFormat:
        fmt_min = float(fmt_thresholds.get(fmt.value, 0.80))
        fm = metrics.per_format.get(fmt)
        if fm is None or fm.total_gaps == 0:
            continue
        if fm.detection_rate is not None and fm.detection_rate < fmt_min:
            breaches.append(
                f"{fmt.value} detection_rate={fm.detection_rate:.1%} "
                f"< threshold {fmt_min:.0%}"
            )

    # Latency budget.
    budget_ms = float(thresholds.get("deterministic_budget_ms", 2000))
    p95_s = metrics.latency.p95_s
    if p95_s is not None and p95_s * 1000 > budget_ms:
        breaches.append(
            f"latency_p95={p95_s * 1000:.1f}ms > budget {budget_ms:.0f}ms"
        )

    return breaches


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pipelineshield.benchmark",
        description=(
            "Seeded corpus detection benchmark harness. "
            "Exits 0 on pass, 1 on gate breach, 2 on harness fault."
        ),
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=_DEFAULT_CORPUS_ROOT,
        help="Root directory of the benchmark corpus (default: corpus/ alongside this module)",
    )
    parser.add_argument(
        "--catalogue-path",
        type=Path,
        default=_DEFAULT_CATALOGUE_PATH,
        help="Path to catalogue_v1.json (default: tests/fixtures/catalogue_v1.json)",
    )
    parser.add_argument(
        "--catalogue-version",
        type=int,
        default=1,
        help="Integer version label stamped in the JSON report (default: 1)",
    )
    parser.add_argument(
        "--thresholds-path",
        type=Path,
        default=_DEFAULT_THRESHOLDS_PATH,
        help="Path to thresholds.yaml (default: thresholds.yaml alongside this module)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark_report.json"),
        help="Path for the JSON report output (default: benchmark_report.json)",
    )
    parser.add_argument(
        "--tolerance",
        type=int,
        default=None,
        help="Anchor-line tolerance in lines (overrides thresholds.yaml value)",
    )
    parser.add_argument(
        "--overall-min-detection",
        type=float,
        default=None,
        help="Overall minimum detection rate 0–1 (overrides thresholds.yaml)",
    )
    parser.add_argument(
        "--deterministic-budget-ms",
        type=float,
        default=None,
        help="p95 latency budget in ms (overrides thresholds.yaml)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="Warm-up iterations discarded before latency recording (default: 3)",
    )
    parser.add_argument(
        "--timed",
        type=int,
        default=5,
        help="Timed iterations per case for latency measurement (default: 5)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress text summary output to stdout",
    )
    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Run the benchmark harness and return the exit code.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        0 (pass), 1 (gate breach), or 2 (harness fault).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Load thresholds.
    thresholds = load_thresholds(args.thresholds_path)

    # Apply CLI overrides.
    if args.tolerance is not None:
        thresholds["anchor_tolerance_lines"] = args.tolerance
    if args.overall_min_detection is not None:
        thresholds["overall_min_detection"] = args.overall_min_detection
    if args.deterministic_budget_ms is not None:
        thresholds["deterministic_budget_ms"] = args.deterministic_budget_ms

    tolerance = int(thresholds.get("anchor_tolerance_lines", 2))

    # Load catalogue.
    catalogue = load_catalogue(args.catalogue_path)

    # Discover corpus.
    try:
        cases = load_corpus_manifests(args.corpus_root, catalogue)
    except ManifestValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_HARNESS_FAULT

    # Run all cases.
    case_results = []
    for case_dir, manifest in cases:
        result = run_case(
            case_dir=case_dir,
            manifest=manifest,
            warmup=args.warmup,
            timed=args.timed,
        )
        case_results.append(result)

    # Check for case-level errors (harness faults, not gate breaches).
    hard_errors = [r for r in case_results if r.case_error]
    if hard_errors:
        for r in hard_errors:
            print(
                f"ERROR in case {r.case_path}: {r.case_error}",
                file=sys.stderr,
            )
        # Still compute metrics and report, but exit 2.

    # Compute metrics.
    metrics = compute_metrics(case_results, catalogue, tolerance=tolerance)

    # Compute corpus checksum.
    corpus_checksum = compute_corpus_checksum(args.corpus_root)

    # Write JSON report.
    try:
        write_json_report(
            metrics=metrics,
            catalogue=catalogue,
            catalogue_version=args.catalogue_version,
            corpus_checksum=corpus_checksum,
            output_path=args.output,
            tolerance_lines=tolerance,
        )
    except OSError as exc:
        print(f"ERROR: could not write report to {args.output}: {exc}", file=sys.stderr)
        return EXIT_HARNESS_FAULT

    # Evaluate thresholds.
    breaches = evaluate_thresholds(metrics, thresholds)

    # Write text summary.
    if not args.quiet:
        write_text_summary(
            metrics=metrics,
            catalogue_version=args.catalogue_version,
            corpus_checksum=corpus_checksum,
            breached_thresholds=breaches,
        )

    # Determine exit code.
    if hard_errors:
        return EXIT_HARNESS_FAULT
    if breaches:
        return EXIT_GATE_BREACH
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
