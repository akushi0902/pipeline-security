"""WO-046 detection rate gate for the WO-045 seeded benchmark corpus.

Loads the top-level ``ground_truth.yaml`` from tests/fixtures/corpus/, runs
each corpus file through the deterministic analysis path, and reconciles
findings against declared seeded gaps and negative expectations to produce a
machine-readable BenchmarkRun.

Two output artefacts are written:
  benchmark-results/<timestamp>-<git-sha>.json   versioned artefact
  benchmark-results/latest.json                  stable pointer for dashboard

CLI usage::

    python -m pipelineshield.benchmark.gate [OPTIONS]

Exit codes:
    0  All thresholds met.
    1  One or more quality-gate thresholds breached.
    2  Harness fault (bad manifest, empty corpus, analysis exception).

No network egress, no LLM invocation, no database access.
"""
from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

import yaml

from .ground_truth import (
    GroundTruthLoadError,
    GroundTruthManifest,
    PipelineFormat as GTFormat,
    load_ground_truth,
)
from .manifest import PipelineFormat as ManifestFormat
from .matcher import (
    BenchmarkRun,
    CategoryResult,
    FileDetail,
    FileReconciliation,
    FormatResult,
    compute_findings_digest,
    evaluate_thresholds,
    reconcile,
)
from .runner import ValidatedFinding, analyse_lines

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent
_DEFAULT_THRESHOLDS_PATH = _THIS_DIR / "thresholds.yaml"
_DEFAULT_CORPUS_MANIFEST = (
    Path(__file__).resolve().parents[4]
    / "tests"
    / "fixtures"
    / "corpus"
    / "ground_truth.yaml"
)
_DEFAULT_CATALOGUE_PATH = (
    Path(__file__).resolve().parents[4]
    / "tests"
    / "fixtures"
    / "catalogue_v1.json"
)

EXIT_OK = 0
EXIT_GATE_BREACH = 1
EXIT_HARNESS_FAULT = 2

# ---------------------------------------------------------------------------
# Format conversion
# ---------------------------------------------------------------------------

_GT_TO_MANIFEST_FMT: dict[GTFormat, ManifestFormat] = {
    GTFormat.GITHUB_ACTIONS: ManifestFormat.GITHUB_ACTIONS,
    GTFormat.GITLAB_CI: ManifestFormat.GITLAB_CI,
    GTFormat.JENKINS: ManifestFormat.JENKINS,
}


def _to_manifest_fmt(gt_fmt: GTFormat) -> ManifestFormat:
    return _GT_TO_MANIFEST_FMT[gt_fmt]


# ---------------------------------------------------------------------------
# Git SHA helper
# ---------------------------------------------------------------------------


def _current_git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Catalogue helpers
# ---------------------------------------------------------------------------


def _load_catalogue_control_map(catalogue_path: Path) -> dict[str, str]:
    """Return mapping of control_id → category_id."""
    data = json.loads(catalogue_path.read_text(encoding="utf-8"))
    mapping: dict[str, str] = {}
    for cat in data["categories"]:
        for ctrl in cat["controls"]:
            mapping[ctrl["id"]] = cat["id"]
    return mapping


# ---------------------------------------------------------------------------
# Core corpus analysis
# ---------------------------------------------------------------------------


def _analyse_corpus_file(
    file_path: Path,
    gt_fmt: GTFormat,
) -> tuple[list[ValidatedFinding], str | None]:
    """Read and analyse one corpus file.

    Returns:
        (validated_findings, error_message_or_None)
    """
    if not file_path.exists():
        return [], f"File not found: {file_path}"
    try:
        text = file_path.read_text(encoding="utf-8")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = text.splitlines(keepends=False)
        manifest_fmt = _to_manifest_fmt(gt_fmt)
        validated, _ = analyse_lines(lines, manifest_fmt)
        return validated, None
    except Exception as exc:  # noqa: BLE001
        return [], f"Analysis error: {exc}"


# ---------------------------------------------------------------------------
# Aggregate helper
# ---------------------------------------------------------------------------


def _aggregate(
    reconciliations: list[FileReconciliation],
    manifest: GroundTruthManifest,
    ctrl_to_cat: dict[str, str],
    tolerance: int,
    git_sha: str,
    run_timestamp: str,
    catalogue_version: int,
) -> BenchmarkRun:
    """Aggregate per-file reconciliation results into a BenchmarkRun."""

    # Per-format accumulators.
    fmt_tp: dict[str, int] = {}
    fmt_fn: dict[str, int] = {}
    fmt_fp: dict[str, int] = {}
    fmt_na_frags: dict[str, int] = {}
    fmt_na_mismatch: dict[str, int] = {}
    fmt_case_count: dict[str, int] = {}
    for cf in manifest.corpus_files:
        k = cf.format.value
        fmt_tp.setdefault(k, 0)
        fmt_fn.setdefault(k, 0)
        fmt_fp.setdefault(k, 0)
        fmt_na_frags.setdefault(k, 0)
        fmt_na_mismatch.setdefault(k, 0)
        fmt_case_count.setdefault(k, 0)
        fmt_case_count[k] += 1

    # NA fragment count per format from manifest.
    for frag in manifest.unassessable_fragments:
        cf = next((c for c in manifest.corpus_files if c.file == frag.file), None)
        if cf:
            fmt_na_frags[cf.format.value] += 1

    # Per-category accumulators.
    cat_tp: dict[str, int] = {}
    cat_fn: dict[str, int] = {}
    cat_fp: dict[str, int] = {}

    # Derive file→format map from manifest.
    file_fmt_map: dict[str, str] = {cf.file: cf.format.value for cf in manifest.corpus_files}
    file_variant_map: dict[str, str] = {cf.file: cf.variant.value for cf in manifest.corpus_files}

    harness_errors: list[dict[str, str]] = []
    file_details: list[FileDetail] = []

    for r in reconciliations:
        fmt_key = file_fmt_map.get(r.file, "unknown")

        if r.harness_error:
            harness_errors.append({"file": r.file, "error": r.harness_error})
            file_details.append(FileDetail(
                file=r.file,
                format=fmt_key,
                variant=file_variant_map.get(r.file, "unknown"),
                true_positives=0,
                false_negatives=0,
                false_positives=0,
                na_gaps=0,
                harness_error=r.harness_error,
            ))
            continue

        fmt_tp[fmt_key] = fmt_tp.get(fmt_key, 0) + r.tp
        fmt_fn[fmt_key] = fmt_fn.get(fmt_key, 0) + r.fn
        fmt_fp[fmt_key] = fmt_fp.get(fmt_key, 0) + r.fp
        fmt_na_mismatch[fmt_key] = fmt_na_mismatch.get(fmt_key, 0) + len(r.na_mismatches)

        # Category breakdown.
        for pair in r.true_positives:
            cat_id = ctrl_to_cat.get(pair.gap.control_id, "unknown")
            cat_tp[cat_id] = cat_tp.get(cat_id, 0) + 1
        for gap in r.false_negatives:
            cat_id = ctrl_to_cat.get(gap.control_id, "unknown")
            cat_fn[cat_id] = cat_fn.get(cat_id, 0) + 1
        for f in r.false_positives:
            cat_id = ctrl_to_cat.get(f.control_id, "unknown")
            cat_fp[cat_id] = cat_fp.get(cat_id, 0) + 1

        file_details.append(FileDetail(
            file=r.file,
            format=fmt_key,
            variant=file_variant_map.get(r.file, "unknown"),
            true_positives=r.tp,
            false_negatives=r.fn,
            false_positives=r.fp,
            na_gaps=len(r.na_gaps),
            detection_rate=r.detection_rate,
            false_negative_controls=[g.control_id for g in r.false_negatives],
        ))

    # Build FormatResult entries.
    per_format: dict[str, FormatResult] = {}
    for fmt_key in set(list(fmt_tp.keys()) + list(file_fmt_map.values())):
        tp = fmt_tp.get(fmt_key, 0)
        fn = fmt_fn.get(fmt_key, 0)
        fp = fmt_fp.get(fmt_key, 0)
        assessable = tp + fn
        det_rate = tp / assessable if assessable > 0 else None
        prec = tp / (tp + fp) if (tp + fp) > 0 else None
        per_format[fmt_key] = FormatResult(
            format=fmt_key,
            case_count=fmt_case_count.get(fmt_key, 0),
            assessable_gaps=assessable,
            detected_gaps=tp,
            false_negatives=fn,
            false_positives=fp,
            na_fragment_count=fmt_na_frags.get(fmt_key, 0),
            na_mismatch_count=fmt_na_mismatch.get(fmt_key, 0),
            detection_rate=det_rate,
            precision=prec,
            recall=det_rate,
        )

    # Build CategoryResult entries.
    all_cat_ids = set(list(cat_tp.keys()) + list(cat_fn.keys()) + list(cat_fp.keys()))
    per_category: dict[str, CategoryResult] = {}
    for cat_id in all_cat_ids:
        tp = cat_tp.get(cat_id, 0)
        fn = cat_fn.get(cat_id, 0)
        fp = cat_fp.get(cat_id, 0)
        total = tp + fn
        det_rate = tp / total if total > 0 else None
        per_category[cat_id] = CategoryResult(
            category_id=cat_id,
            total_gaps=total,
            detected_gaps=tp,
            false_positives=fp,
            detection_rate=det_rate,
        )

    # Overall metrics.
    total_tp = sum(fmt_tp.values())
    total_fn = sum(fmt_fn.values())
    total_fp = sum(fmt_fp.values())
    total_assessable = total_tp + total_fn
    overall_rate = total_tp / total_assessable if total_assessable > 0 else None
    overall_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else None

    findings_digest = compute_findings_digest(reconciliations)

    return BenchmarkRun(
        corpus_version=manifest.corpus_version,
        catalogue_version=catalogue_version,
        git_commit_sha=git_sha,
        timestamp=run_timestamp,
        tolerance_lines=tolerance,
        overall_detection_rate=overall_rate,
        overall_precision=overall_prec,
        overall_recall=overall_rate,
        overall_false_positives=total_fp,
        per_format=per_format,
        per_category=per_category,
        files=file_details,
        findings_digest=findings_digest,
        harness_errors=harness_errors,
        jenkins_separately_reported=True,
    )


# ---------------------------------------------------------------------------
# Main corpus gate runner
# ---------------------------------------------------------------------------


def run_corpus_gate(
    corpus_root: Path,
    manifest: GroundTruthManifest,
    ctrl_to_cat: dict[str, str],
    tolerance: int = 2,
    git_sha: str = "unknown",
    run_timestamp: str | None = None,
    catalogue_version: int = 1,
) -> BenchmarkRun:
    """Run the detection gate over all corpus files in the manifest.

    Args:
        corpus_root:       Root of the corpus directory.
        manifest:          Loaded and validated GroundTruthManifest.
        ctrl_to_cat:       Mapping of control_id → category_id.
        tolerance:         ±line tolerance for anchor matching.
        git_sha:           Git HEAD sha for stamping the run artefact.
        run_timestamp:     ISO-8601 timestamp; defaults to UTC now.
        catalogue_version: Integer catalogue version to stamp in the run.

    Returns:
        ``BenchmarkRun`` with all per-file and aggregate metrics.
    """
    if run_timestamp is None:
        run_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    reconciliations: list[FileReconciliation] = []

    for cf in manifest.corpus_files:
        file_path = corpus_root / cf.file
        findings, error = _analyse_corpus_file(file_path, cf.format)

        if error:
            recon = FileReconciliation(
                file=cf.file,
                harness_error=error,
            )
        else:
            gaps = manifest.gaps_for_file(cf.file)
            fragments = manifest.fragments_for_file(cf.file)
            recon = reconcile(
                file=cf.file,
                findings=findings,
                seeded_gaps=gaps,
                unassessable_fragments=fragments,
                tolerance=tolerance,
            )

        reconciliations.append(recon)

    return _aggregate(
        reconciliations=reconciliations,
        manifest=manifest,
        ctrl_to_cat=ctrl_to_cat,
        tolerance=tolerance,
        git_sha=git_sha,
        run_timestamp=run_timestamp,
        catalogue_version=catalogue_version,
    )


# ---------------------------------------------------------------------------
# Artefact writing
# ---------------------------------------------------------------------------


def write_run_artefacts(run: BenchmarkRun, output_dir: Path) -> Path:
    """Write versioned + latest JSON artefacts.

    Args:
        run:        Completed benchmark run.
        output_dir: Directory to write artefacts into (created if absent).

    Returns:
        Path to the versioned (timestamped) artefact.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Timestamp slug: strip colons/periods for filesystem safety.
    ts_slug = run.timestamp.replace(":", "").replace(".", "")[:17]
    sha_slug = run.git_commit_sha[:7] if run.git_commit_sha != "unknown" else "unk"
    versioned_name = f"{ts_slug}-{sha_slug}.json"
    versioned_path = output_dir / versioned_name
    latest_path = output_dir / "latest.json"

    payload = run.model_dump(mode="json")
    json_bytes = json.dumps(payload, indent=2, ensure_ascii=True)

    versioned_path.write_text(json_bytes, encoding="utf-8")
    latest_path.write_text(json_bytes, encoding="utf-8")

    return versioned_path


# ---------------------------------------------------------------------------
# Summary text
# ---------------------------------------------------------------------------


def _rate_str(rate: float | None) -> str:
    return f"{rate * 100:.1f}%" if rate is not None else "N/A"


def print_summary(
    run: BenchmarkRun,
    breaches: list[str],
    output: Any = None,
) -> None:
    """Print a human-readable detection summary table."""
    out = output or sys.stdout

    def _w(line: str = "") -> None:
        out.write(line + "\n")

    _w("=" * 72)
    _w("PipelineShield WO-046 Detection Rate Gate — Corpus Report")
    _w("=" * 72)
    _w(f"  Corpus version   : {run.corpus_version}")
    _w(f"  Catalogue version: {run.catalogue_version}")
    _w(f"  Git SHA          : {run.git_commit_sha}")
    _w(f"  Timestamp        : {run.timestamp}")
    _w(f"  Tolerance        : ±{run.tolerance_lines} lines")
    _w(f"  Findings digest  : {run.findings_digest[:16]}…")
    _w()

    _w("── Aggregate ─────────────────────────────────────────────────────────")
    _w(f"  Overall detection rate : {_rate_str(run.overall_detection_rate)}")
    _w(f"  Overall precision      : {_rate_str(run.overall_precision)}")
    _w(f"  Overall false positives: {run.overall_false_positives}")
    _w()

    _w("── Detection by Format ───────────────────────────────────────────────")
    for fmt_name, fr in sorted(run.per_format.items()):
        _w(
            f"  {fmt_name:<24} {_rate_str(fr.detection_rate):>8}  "
            f"({fr.detected_gaps}/{fr.assessable_gaps} gaps,"
            f" FP={fr.false_positives})"
        )
    _w()
    _w("  NOTE: Jenkins is always reported separately and never folded into")
    _w("        the overall headline detection rate for aggregate display.")
    _w()

    _w("── Detection by Category ─────────────────────────────────────────────")
    for cat_id, cr in sorted(run.per_category.items()):
        if cr.total_gaps > 0:
            _w(
                f"  {cat_id:<30} {_rate_str(cr.detection_rate):>8}  "
                f"({cr.detected_gaps}/{cr.total_gaps}  FP={cr.false_positives})"
            )
    _w()

    if run.harness_errors:
        _w("── Harness Errors ────────────────────────────────────────────────────")
        for err in run.harness_errors:
            _w(f"  {err.get('file', '?')}: {err.get('error', '?')}")
        _w()

    if breaches:
        _w("── THRESHOLD BREACHES ────────────────────────────────────────────────")
        for breach in breaches:
            _w(f"  ✗ {breach}")
        _w()
        _w("RESULT: FAIL — quality gate breached (exit code 1)")
    else:
        _w("RESULT: PASS — all thresholds met")
    _w("=" * 72)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pipelineshield.benchmark.gate",
        description=(
            "WO-046 detection rate gate. "
            "Exits 0 on pass, 1 on gate breach, 2 on harness fault."
        ),
    )
    parser.add_argument(
        "--corpus-manifest",
        type=Path,
        default=_DEFAULT_CORPUS_MANIFEST,
        help="Path to ground_truth.yaml (default: tests/fixtures/corpus/ground_truth.yaml)",
    )
    parser.add_argument(
        "--catalogue-path",
        type=Path,
        default=_DEFAULT_CATALOGUE_PATH,
        help="Path to catalogue_v1.json",
    )
    parser.add_argument(
        "--catalogue-version",
        type=int,
        default=1,
        help="Integer catalogue version label (default: 1)",
    )
    parser.add_argument(
        "--thresholds-path",
        type=Path,
        default=_DEFAULT_THRESHOLDS_PATH,
        help="Path to thresholds.yaml",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmark-results"),
        help="Directory for JSON artefacts (default: benchmark-results/)",
    )
    parser.add_argument(
        "--tolerance",
        type=int,
        default=None,
        help="Anchor-line tolerance (overrides thresholds.yaml)",
    )
    parser.add_argument(
        "--overall-min",
        type=float,
        default=None,
        help="Overall minimum detection rate [0-1] (overrides thresholds.yaml)",
    )
    parser.add_argument(
        "--max-false-positives",
        type=int,
        default=None,
        help="Maximum false positive count (overrides thresholds.yaml)",
    )
    parser.add_argument(
        "--format-min",
        type=float,
        default=None,
        help=(
            "Set all per-format minimum detection rates to this value [0-1] "
            "(overrides thresholds.yaml format_min_detection for all formats)"
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress summary output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the WO-046 detection gate and return the exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Load thresholds.
    if not args.thresholds_path.exists():
        print(
            f"ERROR: thresholds file not found: {args.thresholds_path}",
            file=sys.stderr,
        )
        return EXIT_HARNESS_FAULT
    try:
        thresholds: dict[str, Any] = yaml.safe_load(
            args.thresholds_path.read_text(encoding="utf-8")
        ) or {}
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: could not parse thresholds: {exc}", file=sys.stderr)
        return EXIT_HARNESS_FAULT

    if args.tolerance is not None:
        thresholds["anchor_tolerance_lines"] = args.tolerance
    if args.overall_min is not None:
        thresholds["overall_min_detection"] = args.overall_min
    if args.max_false_positives is not None:
        thresholds["max_false_positives"] = args.max_false_positives
    if args.format_min is not None:
        thresholds["format_min_detection"] = {
            "github_actions": args.format_min,
            "gitlab_ci": args.format_min,
            "jenkins": args.format_min,
        }

    tolerance = int(thresholds.get("anchor_tolerance_lines", 2))

    # Load manifest.
    try:
        manifest = load_ground_truth(args.corpus_manifest)
    except GroundTruthLoadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_HARNESS_FAULT

    if not manifest.corpus_files:
        print("ERROR: corpus is empty — no files declared in manifest.", file=sys.stderr)
        return EXIT_HARNESS_FAULT

    # Load catalogue.
    if not args.catalogue_path.exists():
        print(f"ERROR: catalogue not found: {args.catalogue_path}", file=sys.stderr)
        return EXIT_HARNESS_FAULT
    ctrl_to_cat = _load_catalogue_control_map(args.catalogue_path)

    corpus_root = args.corpus_manifest.parent

    # Run gate.
    git_sha = _current_git_sha()
    run = run_corpus_gate(
        corpus_root=corpus_root,
        manifest=manifest,
        ctrl_to_cat=ctrl_to_cat,
        tolerance=tolerance,
        git_sha=git_sha,
        catalogue_version=args.catalogue_version,
    )

    # Write artefacts.
    try:
        versioned_path = write_run_artefacts(run, args.output_dir)
    except OSError as exc:
        print(f"ERROR: could not write artefacts to {args.output_dir}: {exc}", file=sys.stderr)
        return EXIT_HARNESS_FAULT

    # Evaluate thresholds.
    breaches = evaluate_thresholds(run, thresholds)

    # Print summary.
    if not args.quiet:
        print_summary(run, breaches)
        print(f"\nArtefact written: {versioned_path}", file=sys.stderr)

    if run.harness_errors:
        return EXIT_HARNESS_FAULT
    if breaches:
        return EXIT_GATE_BREACH
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
