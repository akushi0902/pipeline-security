"""Deterministic-path runner for the benchmark harness.

Executes the analysis pipeline over a single corpus case:
  1. Reads the pipeline definition file.
  2. Normalises line endings (CRLF → LF) so expected_line matching is stable.
  3. Runs the built-in rule pack against the raw text and parsed structure.
  4. Runs the anchor validator: every finding must resolve a real line.
  5. Returns a ``CaseResult`` with validated findings, suppression report, and
     monotonic wall-clock timings.

Latency measurement:
  The runner performs at least ``WARMUP_ITERATIONS`` executions before
  recording timings so import-time and JIT skew is excluded.  Only the
  timed iterations contribute to reported latency.

No LLM, no database, no network — purely deterministic.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .manifest import (
    CaseManifest,
    DEFINITION_FILENAME,
    PipelineFormat,
    UnassessableFragment,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Number of warm-up iterations discarded before latency recording begins.
WARMUP_ITERATIONS: int = 3

#: Number of timed iterations for latency measurement.
TIMED_ITERATIONS: int = 5


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawFinding:
    """An unvalidated finding emitted by a rule."""

    control_id: str
    start_line: int  # 1-based
    rule_id: str
    detail: str = ""


@dataclass(frozen=True)
class ValidatedFinding:
    """A finding that has passed anchor validation."""

    control_id: str
    start_line: int  # 1-based
    anchor_text: str  # the line text at start_line
    rule_id: str
    detail: str = ""


@dataclass
class SuppressionReport:
    """Summary of findings suppressed by the anchor validator."""

    unanchored_findings: list[RawFinding] = field(default_factory=list)


@dataclass
class CoverageReport:
    """Not-Assessable coverage information for a case."""

    format: PipelineFormat
    unassessable_fragments: list[UnassessableFragment] = field(default_factory=list)
    total_lines: int = 0

    @property
    def unassessable_line_count(self) -> int:
        return sum(
            f.line_end - f.line_start + 1 for f in self.unassessable_fragments
        )

    @property
    def assessable_weight_ratio(self) -> float:
        if self.total_lines == 0:
            return 1.0
        return max(0.0, 1.0 - self.unassessable_line_count / self.total_lines)


@dataclass
class CaseResult:
    """Result of running the deterministic path over a single corpus case.

    Attributes:
        case_path: Filesystem path to the corpus case directory.
        manifest: The loaded ground-truth manifest.
        validated_findings: Findings that passed anchor validation.
        suppression_report: Findings discarded by the anchor gate.
        coverage_report: Not-Assessable fragment accounting.
        iteration_times_s: Per-iteration elapsed seconds (timed, not warm-up).
        case_error: Set if the case failed with an exception; other fields
            may be empty when this is non-None.
    """

    case_path: Path
    manifest: CaseManifest
    validated_findings: list[ValidatedFinding] = field(default_factory=list)
    suppression_report: SuppressionReport = field(
        default_factory=SuppressionReport
    )
    coverage_report: CoverageReport = field(
        default_factory=lambda: CoverageReport(format=PipelineFormat.GITHUB_ACTIONS)
    )
    iteration_times_s: list[float] = field(default_factory=list)
    case_error: str | None = None

    @property
    def case_name(self) -> str:
        return self.case_path.name

    @property
    def format_name(self) -> str:
        return self.case_path.parent.name


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RunnerError(RuntimeError):
    """Raised when the runner encounters a non-recoverable harness fault."""


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

# Patterns for presence-based detection (hardcoded secrets, unpinned actions).
# Each entry: (rule_id, control_id, compiled regex)
# The regex is applied to individual lines; the line number of the match
# is emitted as the finding anchor.

_SECRET_KEY_PATTERN = re.compile(
    r"""(?ix)
    (?:^|['":\s])
    (?:api[_\-]?key|password|passwd|secret|token|credential|auth[_\-]?token|
       db[_\-]?pass(?:word)?|access[_\-]?key|private[_\-]?key)
    \s*[:=]\s*
    (?!['"]?\s*[${{]|None|null|true|false|""|'')  # skip env-var references and empty
    ['"]?([A-Za-z0-9+/=_\-]{8,})
    """,
    re.VERBOSE | re.IGNORECASE,
)

# GitHub/GitLab actions/components pinned to a tag (vX.Y.Z) rather than a SHA.
_UNPINNED_ACTION_GH = re.compile(
    r"uses\s*:\s*[\w/.\-]+@v\d",
    re.IGNORECASE,
)

# GitLab unpinned image (tag instead of digest).
_UNPINNED_IMAGE_GL = re.compile(
    r"^\s*image\s*:\s*[\w./\-:]+(?<!@sha256:\w{64})\s*$",
)

# Jenkins unpinned image.
_UNPINNED_IMAGE_JK = re.compile(
    r"docker\s*\.\s*image\s*\(\s*['\"][\w./\-:]+(?!@sha256)['\"]",
    re.IGNORECASE,
)

_HARDCODED_GROOVY_SECRET = re.compile(
    r"(?:withCredentials|password|secret|apiKey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{8,}['\"]",
    re.IGNORECASE,
)

# Tools that constitute "secrets scanning" in a pipeline.
_SECRETS_SCAN_TOOLS = re.compile(
    r"gitleaks|trufflehog|detect-secrets|secretlint|ggshield|talisman",
    re.IGNORECASE,
)
# Artifact signing tools.
_SIGNING_TOOLS = re.compile(
    r"cosign|sigstore|notation|slsa-verifier",
    re.IGNORECASE,
)
# Provenance attestation.
_PROVENANCE_TOOLS = re.compile(
    r"slsa|provenance|in-toto|attest",
    re.IGNORECASE,
)
# SAST tools.
_SAST_TOOLS = re.compile(
    r"semgrep|codeql|bandit|sonarqube|snyk\s+code|checkmarx",
    re.IGNORECASE,
)
# SCA / dependency scanning.
_SCA_TOOLS = re.compile(
    r"trivy|grype|snyk|dependabot|safety|owasp\s+dependency",
    re.IGNORECASE,
)
# Container scanning.
_CONTAINER_SCAN_TOOLS = re.compile(
    r"trivy\s+image|grype|anchore|clair|docker\s+scan",
    re.IGNORECASE,
)
# IaC scanning.
_IAC_TOOLS = re.compile(
    r"checkov|tfsec|terrascan|kics|conftest|trivy\s+config",
    re.IGNORECASE,
)
# SBOM generation.
_SBOM_TOOLS = re.compile(
    r"syft|cyclonedx|spdx|sbom|bom",
    re.IGNORECASE,
)
# Approval gate indicators.
_APPROVAL_GATE_GH = re.compile(
    r"environment\s*:",
    re.IGNORECASE,
)
_APPROVAL_GATE_GL = re.compile(
    r"when\s*:\s*manual|needs\s*:\s*\[.*\]|environment\s*:",
    re.IGNORECASE,
)
_APPROVAL_GATE_JK = re.compile(
    r"input\s*\{|timeout\s*\(|waitForQualityGate",
    re.IGNORECASE,
)
# Least-privilege: overly permissive token (write-all or contents:write at top).
_PERMISSIVE_TOKEN_GH = re.compile(
    r"permissions\s*:\s*write-all|contents\s*:\s*write",
    re.IGNORECASE,
)
# Least-privilege: ephemeral credentials (OIDC / workload identity).
_EPHEMERAL_CREDS_GH = re.compile(
    r"id-token\s*:\s*write|aws-actions/configure-aws-credentials|"
    r"google-github-actions/auth|azure/login",
    re.IGNORECASE,
)
_EPHEMERAL_CREDS_GL = re.compile(
    r"id_tokens\s*:|OIDC|workload.identity",
    re.IGNORECASE,
)
_EPHEMERAL_CREDS_JK = re.compile(
    r"withAWS|assumeRole|workloadIdentity",
    re.IGNORECASE,
)


def _apply_line_rules(
    lines: list[str], fmt: PipelineFormat
) -> list[RawFinding]:
    """Scan lines for presence-based findings (secrets, unpinned actions)."""
    findings: list[RawFinding] = []
    for i, line in enumerate(lines, start=1):
        # sh-001: hardcoded secret
        if _SECRET_KEY_PATTERN.search(line):
            findings.append(
                RawFinding(
                    control_id="sh-001",
                    start_line=i,
                    rule_id="sh-001/hardcoded-secret",
                    detail=f"Potential hardcoded secret at line {i}",
                )
            )
        # sci-001: unpinned action (GitHub)
        if fmt == PipelineFormat.GITHUB_ACTIONS and _UNPINNED_ACTION_GH.search(line):
            findings.append(
                RawFinding(
                    control_id="sci-001",
                    start_line=i,
                    rule_id="sci-001/unpinned-action",
                    detail=f"Unpinned action reference at line {i}",
                )
            )
        # lp-001: overly permissive permissions (GitHub)
        if fmt == PipelineFormat.GITHUB_ACTIONS and _PERMISSIVE_TOKEN_GH.search(line):
            findings.append(
                RawFinding(
                    control_id="lp-001",
                    start_line=i,
                    rule_id="lp-001/permissive-token",
                    detail=f"Overly permissive token permissions at line {i}",
                )
            )

    return findings


def _find_anchor_line(lines: list[str], keyword: str) -> int:
    """Return 1-based line number of first occurrence of ``keyword`` in lines."""
    for i, line in enumerate(lines, start=1):
        if keyword in line:
            return i
    return 1  # fallback to line 1


def _apply_absence_rules(
    lines: list[str], fmt: PipelineFormat
) -> list[RawFinding]:
    """Check for absent controls and emit findings at contextual anchors."""
    full_text = "\n".join(lines)
    findings: list[RawFinding] = []

    # Anchor for "job-level" absence findings: first steps: keyword
    if fmt == PipelineFormat.GITHUB_ACTIONS:
        job_anchor = _find_anchor_line(lines, "    steps:")
        jobs_anchor = _find_anchor_line(lines, "jobs:")

        if not _SECRETS_SCAN_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sh-002",
                    start_line=job_anchor,
                    rule_id="sh-002/no-secrets-scan",
                    detail="No secrets scanning tool found in pipeline",
                )
            )
        if not _SIGNING_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="as-001",
                    start_line=job_anchor,
                    rule_id="as-001/no-signing",
                    detail="No artifact signing tool found in pipeline",
                )
            )
        if not _PROVENANCE_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="as-002",
                    start_line=job_anchor,
                    rule_id="as-002/no-provenance",
                    detail="No provenance attestation found in pipeline",
                )
            )
        if not _SAST_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sa-001",
                    start_line=job_anchor,
                    rule_id="sa-001/no-sast",
                    detail="No SAST tool found in pipeline",
                )
            )
        if not _SCA_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="ds-001",
                    start_line=job_anchor,
                    rule_id="ds-001/no-sca",
                    detail="No SCA/dependency scanning tool found in pipeline",
                )
            )
        if not _IAC_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="iac-001",
                    start_line=job_anchor,
                    rule_id="iac-001/no-iac-scan",
                    detail="No IaC scanning tool found in pipeline",
                )
            )
        if not _SBOM_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sbom-001",
                    start_line=job_anchor,
                    rule_id="sbom-001/no-sbom",
                    detail="No SBOM generation tool found in pipeline",
                )
            )
        if not _APPROVAL_GATE_GH.search(full_text):
            findings.append(
                RawFinding(
                    control_id="ag-001",
                    start_line=jobs_anchor,
                    rule_id="ag-001/no-approval-gate",
                    detail="No environment-based approval gate found",
                )
            )
        if not _EPHEMERAL_CREDS_GH.search(full_text):
            findings.append(
                RawFinding(
                    control_id="lp-002",
                    start_line=job_anchor,
                    rule_id="lp-002/no-ephemeral-creds",
                    detail="No ephemeral/OIDC credentials found",
                )
            )

    elif fmt == PipelineFormat.GITLAB_CI:
        stage_anchor = _find_anchor_line(lines, "stages:")
        script_anchor = _find_anchor_line(lines, "  script:")

        if not _SECRETS_SCAN_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sh-002",
                    start_line=script_anchor,
                    rule_id="sh-002/no-secrets-scan",
                    detail="No secrets scanning tool found in pipeline",
                )
            )
        if not _SIGNING_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="as-001",
                    start_line=script_anchor,
                    rule_id="as-001/no-signing",
                    detail="No artifact signing tool found in pipeline",
                )
            )
        if not _PROVENANCE_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="as-002",
                    start_line=script_anchor,
                    rule_id="as-002/no-provenance",
                    detail="No provenance attestation found in pipeline",
                )
            )
        if not _SAST_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sa-001",
                    start_line=script_anchor,
                    rule_id="sa-001/no-sast",
                    detail="No SAST tool found in pipeline",
                )
            )
        if not _SCA_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="ds-001",
                    start_line=script_anchor,
                    rule_id="ds-001/no-sca",
                    detail="No SCA/dependency scanning tool found in pipeline",
                )
            )
        if not _IAC_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="iac-001",
                    start_line=script_anchor,
                    rule_id="iac-001/no-iac-scan",
                    detail="No IaC scanning tool found in pipeline",
                )
            )
        if not _SBOM_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sbom-001",
                    start_line=script_anchor,
                    rule_id="sbom-001/no-sbom",
                    detail="No SBOM generation found in pipeline",
                )
            )
        if not _APPROVAL_GATE_GL.search(full_text):
            findings.append(
                RawFinding(
                    control_id="ag-001",
                    start_line=stage_anchor,
                    rule_id="ag-001/no-approval-gate",
                    detail="No manual approval gate found",
                )
            )
        if not _EPHEMERAL_CREDS_GL.search(full_text):
            findings.append(
                RawFinding(
                    control_id="lp-002",
                    start_line=script_anchor,
                    rule_id="lp-002/no-ephemeral-creds",
                    detail="No ephemeral/OIDC credentials found",
                )
            )

    elif fmt == PipelineFormat.JENKINS:
        pipeline_anchor = _find_anchor_line(lines, "pipeline {")
        stages_anchor = _find_anchor_line(lines, "    stages {")

        if not _SECRETS_SCAN_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sh-002",
                    start_line=stages_anchor,
                    rule_id="sh-002/no-secrets-scan",
                    detail="No secrets scanning tool found in pipeline",
                )
            )
        if not _SIGNING_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="as-001",
                    start_line=stages_anchor,
                    rule_id="as-001/no-signing",
                    detail="No artifact signing tool found in pipeline",
                )
            )
        if not _SAST_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sa-001",
                    start_line=stages_anchor,
                    rule_id="sa-001/no-sast",
                    detail="No SAST tool found in pipeline",
                )
            )
        if not _SCA_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="ds-001",
                    start_line=stages_anchor,
                    rule_id="ds-001/no-sca",
                    detail="No SCA/dependency scanning tool found in pipeline",
                )
            )
        if not _SBOM_TOOLS.search(full_text):
            findings.append(
                RawFinding(
                    control_id="sbom-001",
                    start_line=stages_anchor,
                    rule_id="sbom-001/no-sbom",
                    detail="No SBOM generation found in pipeline",
                )
            )
        if not _APPROVAL_GATE_JK.search(full_text):
            findings.append(
                RawFinding(
                    control_id="ag-001",
                    start_line=pipeline_anchor,
                    rule_id="ag-001/no-approval-gate",
                    detail="No manual approval gate (input{}) found",
                )
            )

        # Groovy scripted blocks are not assessable for sh-001 / sci-001 /
        # lp-001 — those rules only run on declarative syntax.
        if _HARDCODED_GROOVY_SECRET.search(full_text):
            for i, line in enumerate(lines, start=1):
                if _HARDCODED_GROOVY_SECRET.search(line):
                    findings.append(
                        RawFinding(
                            control_id="sh-001",
                            start_line=i,
                            rule_id="sh-001/hardcoded-secret-groovy",
                            detail=f"Potential hardcoded secret in Groovy at line {i}",
                        )
                    )

    return findings


def _validate_anchors(
    raw_findings: list[RawFinding],
    lines: list[str],
) -> tuple[list[ValidatedFinding], SuppressionReport]:
    """Validate that each finding references a real line in the source.

    A finding is suppressed (not validated) if its ``start_line`` is outside
    the range ``[1, len(lines)]``.
    """
    validated: list[ValidatedFinding] = []
    suppression = SuppressionReport()

    for rf in raw_findings:
        if 1 <= rf.start_line <= len(lines):
            anchor_text = lines[rf.start_line - 1].rstrip("\n")
            validated.append(
                ValidatedFinding(
                    control_id=rf.control_id,
                    start_line=rf.start_line,
                    anchor_text=anchor_text,
                    rule_id=rf.rule_id,
                    detail=rf.detail,
                )
            )
        else:
            suppression.unanchored_findings.append(rf)

    return validated, suppression


# ---------------------------------------------------------------------------
# Definition reader
# ---------------------------------------------------------------------------


def _read_definition(case_dir: Path, manifest: CaseManifest) -> list[str]:
    """Read the pipeline definition, normalising CRLF to LF.

    Returns a list of lines (with trailing newline stripped internally during
    processing; the list preserves newlines for line counting purposes).
    """
    filename = DEFINITION_FILENAME[manifest.format]
    definition_path = case_dir / filename
    if not definition_path.exists():
        raise RunnerError(
            f"Definition file not found: {definition_path}"
        )
    text = definition_path.read_text(encoding="utf-8")
    # Normalise CRLF so expected_line matching is not shifted by Windows endings.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.splitlines(keepends=False)


# ---------------------------------------------------------------------------
# Core single-case runner
# ---------------------------------------------------------------------------


def _run_analysis(
    lines: list[str], manifest: CaseManifest
) -> tuple[list[ValidatedFinding], SuppressionReport]:
    """Execute the deterministic analysis pipeline once."""
    fmt = manifest.format
    raw: list[RawFinding] = []
    raw.extend(_apply_line_rules(lines, fmt))
    raw.extend(_apply_absence_rules(lines, fmt))
    return _validate_anchors(raw, lines)


def analyse_lines(
    lines: list[str],
    fmt: PipelineFormat,
) -> tuple[list[ValidatedFinding], SuppressionReport]:
    """Public entry point for single-pass deterministic analysis.

    Suitable for callers that hold the file lines directly (e.g. the WO-046
    detection gate) rather than a per-case corpus directory layout.

    Args:
        lines: Source lines (CRLF normalised, newlines stripped).
        fmt:   Detected pipeline format.

    Returns:
        Tuple of ``(validated_findings, suppression_report)``.
    """
    raw: list[RawFinding] = []
    raw.extend(_apply_line_rules(lines, fmt))
    raw.extend(_apply_absence_rules(lines, fmt))
    return _validate_anchors(raw, lines)


def run_case(
    case_dir: Path,
    manifest: CaseManifest,
    warmup: int = WARMUP_ITERATIONS,
    timed: int = TIMED_ITERATIONS,
) -> CaseResult:
    """Run the deterministic path over a single corpus case.

    Performs ``warmup`` warm-up iterations (discarded) then ``timed``
    iterations whose wall-clock elapsed times are recorded.  Warm-up
    eliminates import-time and cold-cache skew from the latency budget.

    Args:
        case_dir: Path to the corpus case directory.
        manifest: Validated ground-truth manifest for the case.
        warmup: Number of iterations to discard (default 3).
        timed: Number of iterations to time (default 5).

    Returns:
        ``CaseResult`` populated with validated findings, suppression report,
        coverage report, and per-iteration latency measurements.

    Note:
        Exceptions during analysis are caught and stored in
        ``CaseResult.case_error`` rather than propagated, so a crashing rule
        never silently masquerades as a passing run.
    """
    try:
        lines = _read_definition(case_dir, manifest)
    except RunnerError as exc:
        return CaseResult(
            case_path=case_dir,
            manifest=manifest,
            case_error=str(exc),
        )

    # Warm-up iterations (discarded).
    for _ in range(warmup):
        try:
            _run_analysis(lines, manifest)
        except Exception:  # noqa: BLE001
            pass  # warm-up failures are acceptable; timed run will surface errors

    # Timed iterations.
    iteration_times: list[float] = []
    validated: list[ValidatedFinding] = []
    suppression = SuppressionReport()

    try:
        for iteration in range(timed):
            t0 = time.monotonic()
            validated, suppression = _run_analysis(lines, manifest)
            elapsed = time.monotonic() - t0
            iteration_times.append(elapsed)
    except Exception as exc:  # noqa: BLE001
        return CaseResult(
            case_path=case_dir,
            manifest=manifest,
            case_error=f"Analysis error: {exc}",
        )

    coverage = CoverageReport(
        format=manifest.format,
        unassessable_fragments=list(manifest.unassessable_fragments),
        total_lines=len(lines),
    )

    return CaseResult(
        case_path=case_dir,
        manifest=manifest,
        validated_findings=validated,
        suppression_report=suppression,
        coverage_report=coverage,
        iteration_times_s=iteration_times,
    )
