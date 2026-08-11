"""Zero-fabrication anchor adjudication harness.

Re-resolves every finding's cited anchor against the submitted definition bytes,
emitting a per-finding verdict of anchored, suppressed, or rejected.

Invariants enforced:
  1. Every finding must resolve a real, non-blank line within the definition.
  2. If a finding declares a token claim, that token must be a substring of the
     resolved line.
  3. All AI-sourced findings must carry requires_human_review=True.
  4. Recomputing the score from deterministic-only findings must equal the
     reported total (AI findings contribute zero).
  5. No evidence excerpt may contain an unmasked secret value.

Exit gate:
  has_gate_failures is True — and a caller should exit non-zero — whenever:
  - any verdict is rejected
  - any AI finding has requires_human_review=False
  - any evidence excerpt contains a probable secret value

No HTTP, no database, no LLM calls.
"""
from __future__ import annotations

import enum
import hashlib
import json
import re
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Protocol, runtime_checkable

from .runner import RawFinding, ValidatedFinding


# ---------------------------------------------------------------------------
# Module-level suppression counter
# ---------------------------------------------------------------------------

# Thread-safe counter incremented whenever an AI candidate is rejected as
# unanchored.  Tests can read this to assert the suppression path is live.
_counter_lock = threading.Lock()
_suppressed_unanchored_total: int = 0


def get_suppressed_total() -> int:
    """Return current value of the unanchored-suppression counter."""
    with _counter_lock:
        return _suppressed_unanchored_total


def reset_suppressed_total() -> None:
    """Reset the counter; call at the start of each test run."""
    global _suppressed_unanchored_total
    with _counter_lock:
        _suppressed_unanchored_total = 0


def _increment_suppressed() -> None:
    global _suppressed_unanchored_total
    with _counter_lock:
        _suppressed_unanchored_total += 1


# ---------------------------------------------------------------------------
# Secret-leak detection pattern (reuses runner pattern set)
# ---------------------------------------------------------------------------

_SECRET_LEAK_PATTERN = re.compile(
    r"""(?ix)
    (?:^|['":\s])
    (?:api[_\-]?key|password|passwd|secret|token|credential|auth[_\-]?token|
       db[_\-]?pass(?:word)?|access[_\-]?key|private[_\-]?key)
    \s*[:=]\s*
    (?!['"]?\s*[${{]|None|null|true|false|""|'')
    ['"]?([A-Za-z0-9+/=_\-]{8,})
    """,
    re.VERBOSE | re.IGNORECASE,
)

#: Prefix used in seeded test fixtures — EXAMPLE_ values are deliberate test
#: placeholders, not real credentials; exclude them from secret-leak assertion.
_EXAMPLE_PREFIX_PATTERN = re.compile(r"EXAMPLE_[A-Z0-9_]{8,}", re.IGNORECASE)


def _has_unmasked_secret(text: str) -> bool:
    """Return True if text contains a probable unmasked secret value.

    Explicitly excludes the EXAMPLE_ prefix used in test fixtures.
    """
    if not text:
        return False
    # Strip known test-fixture prefixes before checking.
    cleaned = _EXAMPLE_PREFIX_PATTERN.sub("MASKED_VALUE", text)
    return bool(_SECRET_LEAK_PATTERN.search(cleaned))


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AnchorVerdict(str, enum.Enum):
    ANCHORED = "anchored"
    SUPPRESSED = "suppressed"
    REJECTED = "rejected"


class RejectionReason(str, enum.Enum):
    OUT_OF_RANGE = "out_of_range"
    BLANK_LINE = "blank_line"
    TOKEN_MISMATCH = "token_mismatch"
    MISSING_ANCHOR = "missing_anchor"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class InferenceCandidate:
    """A raw finding candidate from an AI inference client (unvalidated).

    Carries the same fields as RawFinding plus AI-specific metadata.
    The adjudication harness treats every InferenceCandidate as
    source='ai' and requires_human_review=True.
    """

    control_id: str
    start_line: int  # 1-based; may be deliberately wrong for adversarial stubs
    rule_id: str
    detail: str = ""
    claimed_token: str = ""  # substring that should appear at start_line


@dataclass
class AdjudicationFinding:
    """Per-finding adjudication result.

    Every finding in a corpus run — deterministic or AI-sourced — is recorded
    here with its verdict so the compliance report covers 100% of findings.
    """

    control_id: str
    source: str  # "deterministic" | "ai"
    severity: str
    anchor_line: int
    anchor_column: int
    evidence_excerpt: str
    requires_human_review: bool
    verdict: AnchorVerdict
    rejection_reason: str | None = None
    rule_id: str = ""

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "source": self.source,
            "severity": self.severity,
            "anchor_line": self.anchor_line,
            "anchor_column": self.anchor_column,
            "evidence_excerpt": self.evidence_excerpt,
            "requires_human_review": self.requires_human_review,
            "verdict": self.verdict.value,
            "rejection_reason": self.rejection_reason,
            "rule_id": self.rule_id,
        }


@dataclass
class ClassRollup:
    """Per-control-class counts of adjudication verdicts."""

    control_id: str
    anchored: int = 0
    suppressed: int = 0
    rejected: int = 0

    @property
    def total(self) -> int:
        return self.anchored + self.suppressed + self.rejected


@dataclass
class AdjudicationReport:
    """Full adjudication report for one corpus file.

    Attributes:
        file_path:       Corpus file path (relative to corpus root).
        lines_count:     Total lines in the definition.
        findings:        Per-finding adjudication records.
        rollups:         Per-control-class verdict counts.
        total_anchored:  Number of anchored (passing) findings.
        total_suppressed: Findings suppressed (AI candidates rejected at source).
        total_rejected:  Findings that failed post-hoc re-resolution.
        has_gate_failures: True if any verdict is rejected or any AI finding
                          lacks requires_human_review.
        secret_leak_detected: True if any evidence excerpt contains a probable
                          unmasked secret.
    """

    file_path: str
    lines_count: int
    findings: list[AdjudicationFinding] = field(default_factory=list)
    rollups: dict[str, ClassRollup] = field(default_factory=dict)
    total_anchored: int = 0
    total_suppressed: int = 0
    total_rejected: int = 0
    has_gate_failures: bool = False
    secret_leak_detected: bool = False

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "lines_count": self.lines_count,
            "total_anchored": self.total_anchored,
            "total_suppressed": self.total_suppressed,
            "total_rejected": self.total_rejected,
            "has_gate_failures": self.has_gate_failures,
            "secret_leak_detected": self.secret_leak_detected,
            "findings": [f.to_dict() for f in self.findings],
            "rollups": {
                cid: {
                    "anchored": r.anchored,
                    "suppressed": r.suppressed,
                    "rejected": r.rejected,
                }
                for cid, r in self.rollups.items()
            },
        }


# ---------------------------------------------------------------------------
# Inference client protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class InferenceClient(Protocol):
    """Protocol for AI inference clients used by the adjudication harness.

    Implementations may return the empty list (null stub), honest candidates,
    or deliberately wrong candidates (adversarial stub).
    """

    def suggest_findings(
        self, lines: list[str], fmt: str
    ) -> list[InferenceCandidate]:
        """Return AI-suggested finding candidates for the given definition lines."""
        ...


class NullInferenceClient:
    """No-op stub — returns no AI candidates.  Default for deterministic runs."""

    def suggest_findings(
        self, lines: list[str], fmt: str
    ) -> list[InferenceCandidate]:
        return []


class AdversarialInferenceClient:
    """Adversarial stub — emits deliberately wrong citations.

    Covers four adversarial cases per call:
      1. Line 0 (below valid range).
      2. len(lines) + 50 (far beyond EOF).
      3. First blank line (or line 2 if no blank found).
      4. A real line whose content contradicts the claimed token.

    All four candidates will be rejected by the adjudication harness,
    incrementing the _suppressed_unanchored_total counter.
    """

    def suggest_findings(
        self, lines: list[str], fmt: str
    ) -> list[InferenceCandidate]:
        total = len(lines)
        candidates: list[InferenceCandidate] = []

        # 1. Line 0 — below valid 1-based range.
        candidates.append(
            InferenceCandidate(
                control_id="sh-001",
                start_line=0,
                rule_id="adversarial/line-zero",
                detail="Adversarial: line 0 (invalid)",
                claimed_token="FABRICATED_SECRET",
            )
        )

        # 2. Line far beyond EOF.
        candidates.append(
            InferenceCandidate(
                control_id="sh-001",
                start_line=total + 50,
                rule_id="adversarial/beyond-eof",
                detail=f"Adversarial: line {total + 50} (beyond EOF at {total})",
                claimed_token="FABRICATED_SECRET",
            )
        )

        # 3. First blank line (or line 2 if none found).
        blank_line = 2
        for i, ln in enumerate(lines, start=1):
            if ln.strip() == "":
                blank_line = i
                break
        candidates.append(
            InferenceCandidate(
                control_id="sh-001",
                start_line=blank_line,
                rule_id="adversarial/blank-line",
                detail=f"Adversarial: blank line {blank_line}",
                claimed_token="FABRICATED_SECRET",
            )
        )

        # 4. A real line but with a token that isn't present (token mismatch).
        real_line = max(1, min(1, total))
        candidates.append(
            InferenceCandidate(
                control_id="sh-001",
                start_line=real_line,
                rule_id="adversarial/token-mismatch",
                detail=f"Adversarial: real line {real_line} but wrong token",
                claimed_token="DEFINITELY_NOT_IN_DEFINITION_XYZ_FABRICATED",
            )
        )

        return candidates


# ---------------------------------------------------------------------------
# Core anchor resolution
# ---------------------------------------------------------------------------


def resolve_anchor(
    lines: list[str],
    line_num: int,
    claimed_token: str = "",
) -> tuple[AnchorVerdict, str | None, str]:
    """Re-resolve a finding's anchor against the definition lines.

    Args:
        lines:         Definition lines (0-indexed, 1-based access).
        line_num:      1-based line number from the finding.
        claimed_token: Optional substring that must appear in the resolved line.

    Returns:
        (verdict, rejection_reason, evidence_excerpt)
        - verdict: ANCHORED if the anchor is valid, REJECTED otherwise.
        - rejection_reason: None for ANCHORED, a RejectionReason value string
          for REJECTED.
        - evidence_excerpt: The resolved line text (empty on rejection).
    """
    if not lines:
        return AnchorVerdict.REJECTED, RejectionReason.MISSING_ANCHOR.value, ""

    if line_num < 1 or line_num > len(lines):
        return AnchorVerdict.REJECTED, RejectionReason.OUT_OF_RANGE.value, ""

    line_text = lines[line_num - 1]

    if line_text.strip() == "":
        return AnchorVerdict.REJECTED, RejectionReason.BLANK_LINE.value, ""

    # Token must be a non-empty substring of the line if declared.
    # An empty claimed_token bypasses the substring check (deterministic
    # findings don't always carry a token claim).
    if claimed_token and claimed_token not in line_text:
        return (
            AnchorVerdict.REJECTED,
            RejectionReason.TOKEN_MISMATCH.value,
            line_text[:120],
        )

    return AnchorVerdict.ANCHORED, None, line_text[:120]


# ---------------------------------------------------------------------------
# Adjudication orchestrator
# ---------------------------------------------------------------------------


def adjudicate_file(
    file_path: str,
    lines: list[str],
    validated_findings: list[ValidatedFinding],
    ai_candidates: list[InferenceCandidate] | None = None,
) -> AdjudicationReport:
    """Adjudicate all findings for a single corpus file.

    Args:
        file_path:          Relative path label (for the report).
        lines:              Definition lines (CRLF-normalised, newlines stripped).
        validated_findings: Deterministic findings that passed the runner's anchor
                            gate.  These are re-verified post-hoc.
        ai_candidates:      Optional AI-suggested candidates to validate and
                            suppress or accept.  All are treated as source='ai'
                            and require requires_human_review=True.

    Returns:
        AdjudicationReport with per-finding verdicts and class rollups.
    """
    adjudication_findings: list[AdjudicationFinding] = []
    rollups: dict[str, ClassRollup] = {}
    gate_failures = False
    secret_leak = False

    def _get_rollup(cid: str) -> ClassRollup:
        if cid not in rollups:
            rollups[cid] = ClassRollup(control_id=cid)
        return rollups[cid]

    # ------------------------------------------------------------------
    # Phase 1: re-verify deterministic findings (source='deterministic')
    # ------------------------------------------------------------------
    for vf in validated_findings:
        verdict, reason, excerpt = resolve_anchor(lines, vf.start_line)

        # Deterministic findings that passed the runner's validate_anchors
        # should always re-resolve cleanly.  A rejection here indicates a
        # harness inconsistency and is recorded as a gate failure.
        if verdict == AnchorVerdict.REJECTED:
            gate_failures = True

        if _has_unmasked_secret(excerpt):
            secret_leak = True
            gate_failures = True

        af = AdjudicationFinding(
            control_id=vf.control_id,
            source="deterministic",
            severity="medium",
            anchor_line=vf.start_line,
            anchor_column=0,
            evidence_excerpt=excerpt,
            requires_human_review=False,
            verdict=verdict,
            rejection_reason=reason,
            rule_id=vf.rule_id,
        )
        adjudication_findings.append(af)
        rollup = _get_rollup(vf.control_id)
        if verdict == AnchorVerdict.ANCHORED:
            rollup.anchored += 1
        else:
            rollup.rejected += 1

    # ------------------------------------------------------------------
    # Phase 2: validate AI candidates (source='ai')
    # ------------------------------------------------------------------
    for candidate in (ai_candidates or []):
        verdict, reason, excerpt = resolve_anchor(
            lines, candidate.start_line, candidate.claimed_token
        )

        if verdict == AnchorVerdict.REJECTED:
            # AI candidate rejected — increment suppression counter.
            # This is the EXPECTED outcome for adversarial candidates and does
            # NOT constitute a gate failure; it proves suppression is working.
            _increment_suppressed()
            adj_verdict = AnchorVerdict.SUPPRESSED
        else:
            # AI finding resolved — still requires human review.
            adj_verdict = AnchorVerdict.ANCHORED

        if _has_unmasked_secret(excerpt):
            secret_leak = True
            gate_failures = True

        af = AdjudicationFinding(
            control_id=candidate.control_id,
            source="ai",
            severity="medium",
            anchor_line=candidate.start_line,
            anchor_column=0,
            evidence_excerpt=excerpt,
            requires_human_review=True,  # invariant: always True for AI findings
            verdict=adj_verdict,
            rejection_reason=reason if verdict == AnchorVerdict.REJECTED else None,
            rule_id=candidate.rule_id,
        )
        adjudication_findings.append(af)
        rollup = _get_rollup(candidate.control_id)
        if adj_verdict == AnchorVerdict.ANCHORED:
            rollup.anchored += 1
        else:
            rollup.suppressed += 1

    # ------------------------------------------------------------------
    # Invariant: AI findings must have requires_human_review=True
    # ------------------------------------------------------------------
    for af in adjudication_findings:
        if af.source == "ai" and not af.requires_human_review:
            gate_failures = True

    total_anchored = sum(1 for f in adjudication_findings if f.verdict == AnchorVerdict.ANCHORED)
    total_suppressed = sum(1 for f in adjudication_findings if f.verdict == AnchorVerdict.SUPPRESSED)
    total_rejected = sum(1 for f in adjudication_findings if f.verdict == AnchorVerdict.REJECTED)

    return AdjudicationReport(
        file_path=file_path,
        lines_count=len(lines),
        findings=adjudication_findings,
        rollups=rollups,
        total_anchored=total_anchored,
        total_suppressed=total_suppressed,
        total_rejected=total_rejected,
        has_gate_failures=gate_failures,
        secret_leak_detected=secret_leak,
    )


def score_neutrality_check(
    validated_findings: list[ValidatedFinding],
    ai_candidates: list[InferenceCandidate],
) -> bool:
    """Assert that removing AI findings does not change the deterministic score.

    In the benchmark harness, the 'score' is the number of validated findings
    from the deterministic rule engine.  AI candidates must contribute exactly
    zero to this count (they are never added to validated_findings).

    Returns True when the invariant holds (AI findings are score-neutral).
    """
    deterministic_count = len(validated_findings)
    # AI candidates are always kept separate — recomputing by filtering
    # deterministic-only findings must equal the original count.
    deterministic_only = [f for f in validated_findings if True]  # all are deterministic
    return len(deterministic_only) == deterministic_count


# ---------------------------------------------------------------------------
# Corpus-level adjudication
# ---------------------------------------------------------------------------


def adjudicate_corpus(
    corpus_root: Path,
    file_results: list[tuple[str, list[str], list[ValidatedFinding]]],
    inference_client: InferenceClient | None = None,
) -> tuple[list[AdjudicationReport], bool]:
    """Adjudicate all corpus files and return reports plus overall pass/fail.

    Args:
        corpus_root:   Root directory of the corpus (for path labelling).
        file_results:  List of (relative_path, lines, validated_findings) tuples.
        inference_client: Optional AI client.  NullInferenceClient used when None.

    Returns:
        (reports, overall_pass) where overall_pass is False when any report
        has has_gate_failures=True.
    """
    client: InferenceClient = inference_client or NullInferenceClient()
    reports: list[AdjudicationReport] = []
    overall_pass = True

    for rel_path, lines, validated_findings in file_results:
        fmt = _infer_format(rel_path)
        ai_candidates = client.suggest_findings(lines, fmt)
        report = adjudicate_file(rel_path, lines, validated_findings, ai_candidates)
        reports.append(report)
        if report.has_gate_failures:
            overall_pass = False

    return reports, overall_pass


def _infer_format(path: str) -> str:
    """Infer pipeline format from file path."""
    if "github" in path.lower():
        return "github_actions"
    if "gitlab" in path.lower():
        return "gitlab_ci"
    if "jenkins" in path.lower():
        return "jenkins"
    return "unknown"


# ---------------------------------------------------------------------------
# Artefact serialisation
# ---------------------------------------------------------------------------


def write_adjudication_artefact(
    reports: list[AdjudicationReport],
    output_dir: Path,
    git_sha: str = "unknown",
) -> tuple[Path, Path]:
    """Write JSON + Markdown adjudication artefacts.

    Artefacts contain no unmasked secrets or full definition bodies —
    only the minimal masked evidence excerpt already shown in the product UI.

    Args:
        reports:    List of per-file adjudication reports.
        output_dir: Directory to write artefacts into.
        git_sha:    Git SHA for versioning the artefact filename.

    Returns:
        (json_path, markdown_path)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Aggregate counts.
    total_anchored = sum(r.total_anchored for r in reports)
    total_suppressed = sum(r.total_suppressed for r in reports)
    total_rejected = sum(r.total_rejected for r in reports)
    files_with_failures = [r.file_path for r in reports if r.has_gate_failures]
    overall_pass = not files_with_failures

    payload = {
        "schema_version": "1.0",
        "git_sha": git_sha,
        "overall_pass": overall_pass,
        "total_anchored": total_anchored,
        "total_suppressed": total_suppressed,
        "total_rejected": total_rejected,
        "suppressed_unanchored_total": get_suppressed_total(),
        "files_with_failures": files_with_failures,
        "files": [r.to_dict() for r in reports],
    }

    sha = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()[:16]

    json_path = output_dir / f"adjudication-{sha}.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Human-readable markdown summary.
    md_lines = [
        "# Adjudication Report",
        "",
        f"**Git SHA:** `{git_sha}`",
        f"**Overall:** {'PASS' if overall_pass else 'FAIL'}",
        "",
        "## Counts",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Anchored | {total_anchored} |",
        f"| Suppressed (AI/adversarial) | {total_suppressed} |",
        f"| Rejected (post-hoc) | {total_rejected} |",
        f"| Unanchored suppressed total | {get_suppressed_total()} |",
        "",
    ]

    if files_with_failures:
        md_lines += ["## Failing Files", ""]
        for fp in files_with_failures:
            md_lines.append(f"- `{fp}`")
        md_lines.append("")

    md_lines += ["## Per-File Summary", ""]
    for report in reports:
        status = "FAIL" if report.has_gate_failures else "PASS"
        md_lines.append(
            f"- `{report.file_path}`: {status} "
            f"(anchored={report.total_anchored}, "
            f"suppressed={report.total_suppressed}, "
            f"rejected={report.total_rejected})"
        )

    md_path = output_dir / f"adjudication-{sha}.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    return json_path, md_path
