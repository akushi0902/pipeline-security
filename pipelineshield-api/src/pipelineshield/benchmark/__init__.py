"""Benchmark harness for seeded corpus detection quality gate.

Provides:
- Manifest schema and validation (manifest.py)
- Deterministic-path runner (runner.py)
- Metrics computation (metrics.py)
- Report rendering (report.py)
- CLI entry point (cli.py)

Threshold configuration lives in thresholds.yaml.
Corpus lives under corpus/<format>/<variant>/.
"""
from .manifest import (
    CaseManifest,
    ManifestValidationError,
    PipelineFormat,
    SeedGap,
    UnassessableFragment,
    load_corpus_manifests,
    load_manifest,
    validate_manifest_against_catalogue,
)
from .runner import CaseResult, RunnerError, analyse_lines, run_case
from .metrics import BenchmarkMetrics, compute_metrics
from .report import write_json_report, write_text_summary
from .cli import main
from .matcher import (
    BenchmarkRun,
    CategoryResult,
    FileReconciliation,
    FormatResult,
    compute_findings_digest,
    evaluate_thresholds,
    reconcile,
)
from .gate import run_corpus_gate, write_run_artefacts

__all__ = [
    "CaseManifest",
    "ManifestValidationError",
    "PipelineFormat",
    "SeedGap",
    "UnassessableFragment",
    "load_corpus_manifests",
    "load_manifest",
    "validate_manifest_against_catalogue",
    "CaseResult",
    "RunnerError",
    "analyse_lines",
    "run_case",
    "BenchmarkMetrics",
    "compute_metrics",
    "write_json_report",
    "write_text_summary",
    "main",
    # WO-046
    "BenchmarkRun",
    "CategoryResult",
    "FileReconciliation",
    "FormatResult",
    "compute_findings_digest",
    "evaluate_thresholds",
    "reconcile",
    "run_corpus_gate",
    "write_run_artefacts",
]
