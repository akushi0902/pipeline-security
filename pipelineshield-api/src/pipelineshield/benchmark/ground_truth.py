"""Top-level ground-truth manifest schema for the seeded benchmark corpus.

This module defines Pydantic v2 models for the richer WO-045 manifest that
spans ALL corpus files and records:

- ``CorpusFile``           — metadata for each committed pipeline definition.
- ``SeededGap``            — a deliberately-introduced control gap with
                             expected_status, anchor line and rationale.
- ``NegativeExpectation``  — a control that MUST evaluate Present in a given
                             file (measures false positives, not just misses).
- ``UnassessableFragment`` — a code region that the analyser cannot statically
                             assess; findings inside are exempt from scoring.
- ``GroundTruthManifest``  — top-level document covering the full corpus.

This is distinct from the per-case ``CaseManifest`` in ``manifest.py`` (which
describes one variant in isolation).  WO-044 through WO-047 consume both.
"""
from __future__ import annotations

import enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PipelineFormat(str, enum.Enum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"


class Variant(str, enum.Enum):
    INSECURE = "insecure"
    PARTIAL = "partial"
    HARDENED = "hardened"
    NOT_ASSESSABLE = "not_assessable"


class ExpectedStatus(str, enum.Enum):
    MISSING = "missing"
    PARTIAL = "partial"
    PRESENT = "present"
    NOT_ASSESSABLE = "not_assessable"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class SeededGap(BaseModel):
    """A deliberately-seeded control gap in a corpus file.

    Attributes:
        file:                 Relative path of the corpus file (from corpus root).
        control_id:           Catalogue control ID this gap exercises.
        category:             Control category ID for quick cross-referencing.
        severity:             Expected severity.
        expected_status:      How the gap should be classified by the analyser.
        expected_anchor_line: 1-based line number where the finding anchor is
                              expected (within ±tolerance lines).
        rationale:            Human note explaining the seeded weakness.
    """

    file: str = Field(..., min_length=1)
    control_id: str = Field(..., min_length=1, max_length=64)
    category: str = Field(..., min_length=1, max_length=64)
    severity: Severity
    expected_status: ExpectedStatus
    expected_anchor_line: int = Field(..., ge=1)
    rationale: str = Field(..., min_length=1)

    model_config = {"frozen": True}


class NegativeExpectation(BaseModel):
    """A control that must evaluate PRESENT in the given file.

    Used to measure false positives: if any analyser finding reports this
    control as Missing/Partial in this file, it is a false positive.
    """

    file: str = Field(..., min_length=1)
    control_id: str = Field(..., min_length=1, max_length=64)
    category: str = Field(..., min_length=1, max_length=64)
    rationale: str = ""

    model_config = {"frozen": True}


class UnassessableFragment(BaseModel):
    """A region in a corpus file that cannot be statically assessed."""

    file: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _start_lte_end(self) -> "UnassessableFragment":
        if self.line_start > self.line_end:
            raise ValueError(
                f"line_start ({self.line_start}) must be <= line_end ({self.line_end})"
            )
        return self


class CorpusFile(BaseModel):
    """Metadata record for one committed corpus pipeline definition."""

    file: str = Field(..., min_length=1)
    format: PipelineFormat
    variant: Variant
    line_count: int = Field(..., ge=1, le=500)
    description: str = ""

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Top-level manifest
# ---------------------------------------------------------------------------


class GroundTruthManifest(BaseModel):
    """Top-level ground-truth manifest for the benchmark corpus.

    Covers all corpus files, seeded gaps, negative expectations, and
    not-assessable fragments in a single document so gate tests share
    one source of truth.

    Constraints enforced:
    - No duplicate (file, control_id) in seeded_gaps.
    - No duplicate (file, control_id) in negative_expectations.
    - A (file, control_id) pair cannot appear in both seeded_gaps and
      negative_expectations (conflicting expectations).
    - corpus_files entries must have distinct file paths.
    """

    corpus_version: str = Field(..., min_length=1)
    catalogue_version: int = Field(..., ge=1)
    corpus_files: list[CorpusFile] = Field(default_factory=list)
    seeded_gaps: list[SeededGap] = Field(default_factory=list)
    negative_expectations: list[NegativeExpectation] = Field(default_factory=list)
    unassessable_fragments: list[UnassessableFragment] = Field(default_factory=list)

    model_config = {"frozen": True}

    @field_validator("corpus_files", mode="after")
    @classmethod
    def _unique_files(cls, files: list[CorpusFile]) -> list[CorpusFile]:
        seen: set[str] = set()
        for f in files:
            if f.file in seen:
                raise ValueError(f"Duplicate corpus file entry: {f.file!r}")
            seen.add(f.file)
        return files

    @field_validator("seeded_gaps", mode="after")
    @classmethod
    def _no_duplicate_gaps(cls, gaps: list[SeededGap]) -> list[SeededGap]:
        seen: set[tuple[str, str, int]] = set()
        for g in gaps:
            key = (g.file, g.control_id, g.expected_anchor_line)
            if key in seen:
                raise ValueError(
                    f"Duplicate seeded gap: file={g.file!r} control={g.control_id!r} "
                    f"line={g.expected_anchor_line}"
                )
            seen.add(key)
        return gaps

    @field_validator("negative_expectations", mode="after")
    @classmethod
    def _no_duplicate_negatives(
        cls, expects: list[NegativeExpectation]
    ) -> list[NegativeExpectation]:
        seen: set[tuple[str, str]] = set()
        for e in expects:
            key = (e.file, e.control_id)
            if key in seen:
                raise ValueError(
                    f"Duplicate negative expectation: file={e.file!r} control={e.control_id!r}"
                )
            seen.add(key)
        return expects

    @model_validator(mode="after")
    def _no_conflicting_expectations(self) -> "GroundTruthManifest":
        gap_pairs = {(g.file, g.control_id) for g in self.seeded_gaps}
        neg_pairs = {(e.file, e.control_id) for e in self.negative_expectations}
        conflicts = gap_pairs & neg_pairs
        if conflicts:
            raise ValueError(
                f"(file, control_id) pairs appear in both seeded_gaps and "
                f"negative_expectations (conflicting): {sorted(conflicts)!r}"
            )
        return self

    # ------------------------------------------------------------------
    # Derived views
    # ------------------------------------------------------------------

    def gaps_for_file(self, file: str) -> list[SeededGap]:
        return [g for g in self.seeded_gaps if g.file == file]

    def negatives_for_file(self, file: str) -> list[NegativeExpectation]:
        return [e for e in self.negative_expectations if e.file == file]

    def fragments_for_file(self, file: str) -> list[UnassessableFragment]:
        return [f for f in self.unassessable_fragments if f.file == file]

    def files_by_format(self, fmt: PipelineFormat) -> list[CorpusFile]:
        return [f for f in self.corpus_files if f.format == fmt]

    def gaps_by_category(self) -> dict[str, list[SeededGap]]:
        result: dict[str, list[SeededGap]] = {}
        for g in self.seeded_gaps:
            result.setdefault(g.category, []).append(g)
        return result


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class GroundTruthLoadError(ValueError):
    """Raised when the ground_truth.yaml fails loading or validation."""


def load_ground_truth(manifest_path: Path) -> GroundTruthManifest:
    """Load and validate the top-level ground_truth.yaml manifest.

    Args:
        manifest_path: Path to ground_truth.yaml (or .json).

    Returns:
        Validated ``GroundTruthManifest`` instance.

    Raises:
        GroundTruthLoadError: On file-not-found, YAML/JSON parse error,
            or Pydantic validation failure.
    """
    if not manifest_path.exists():
        raise GroundTruthLoadError(f"Ground-truth manifest not found: {manifest_path}")

    try:
        raw: Any = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise GroundTruthLoadError(
            f"YAML parse error in {manifest_path}: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise GroundTruthLoadError(
            f"Ground-truth manifest must be a YAML mapping; got {type(raw).__name__}"
        )

    from pydantic import ValidationError

    try:
        return GroundTruthManifest.model_validate(raw)
    except ValidationError as exc:
        raise GroundTruthLoadError(
            f"Ground-truth manifest schema validation failed: {exc}"
        ) from exc


def validate_ground_truth_against_catalogue(
    manifest: GroundTruthManifest,
    known_control_ids: frozenset[str],
) -> list[str]:
    """Check all control_id references against the active catalogue.

    Returns:
        List of unknown control_id strings (empty = all valid).
    """
    all_ids = (
        {g.control_id for g in manifest.seeded_gaps}
        | {e.control_id for e in manifest.negative_expectations}
    )
    return sorted(all_ids - known_control_ids)
