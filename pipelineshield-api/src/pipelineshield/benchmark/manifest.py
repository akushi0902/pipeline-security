"""Ground-truth manifest schema and validation for the benchmark corpus.

Each corpus case directory contains a ``ground_truth.yaml`` describing:
- ``format``: pipeline format (github_actions | gitlab_ci | jenkins)
- ``variant``: insecure | partial | hardened
- ``seeded_gaps``: list of intentionally-seeded security gaps with
  ``control_id``, ``expected_line`` (1-based), and ``severity``
- ``unassessable_fragments``: fragments excluded from the detection
  denominator (e.g. scripted Groovy blocks in Jenkins)

Manifests are validated before a run; an invalid manifest fails the harness
with exit code 2 (harness fault) and a clear message identifying the case.

Match rule (documented parameter):
  A seeded gap is *detected* when a validated finding shares the gap's
  ``control_id`` AND its anchor ``start_line`` falls within
  ``[expected_line - tolerance, expected_line + tolerance]``
  where ``tolerance`` defaults to 2 lines and is configurable via
  ``thresholds.yaml`` or the CLI.
"""
from __future__ import annotations

import enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from pipelineshield.catalogue.schemas import CatalogueSnapshot

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PipelineFormat(str, enum.Enum):
    """Supported CI/CD pipeline formats."""

    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class SeedGap(BaseModel):
    """A single seeded security gap in a corpus case.

    Attributes:
        control_id: The catalogue control ID this gap exercises.
        expected_line: 1-based line number where the finding anchor is expected.
        severity: Expected severity string (informational only; not re-validated
            here — catalogue validation covers correctness).
        description: Optional human note for the gap.
    """

    control_id: str = Field(..., min_length=1, max_length=64)
    expected_line: int = Field(..., ge=1, description="1-based expected anchor line")
    severity: str = Field(..., min_length=1, max_length=32)
    description: str = ""

    model_config = {"frozen": True}


class UnassessableFragment(BaseModel):
    """A region intentionally excluded from the detection denominator.

    Used for fragments that cannot be statically assessed (e.g. scripted
    Groovy in Jenkins declarative pipelines, unresolved GitLab includes).
    Gaps seeded inside these regions are listed under
    ``expected_unassessable`` in the metrics rather than scored as misses.
    """

    reason: str = Field(..., min_length=1, max_length=255)
    line_start: int = Field(..., ge=1, description="1-based inclusive start line")
    line_end: int = Field(..., ge=1, description="1-based inclusive end line")

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _start_lte_end(self) -> "UnassessableFragment":
        if self.line_start > self.line_end:
            raise ValueError(
                f"UnassessableFragment line_start ({self.line_start}) "
                f"must be <= line_end ({self.line_end})"
            )
        return self


# ---------------------------------------------------------------------------
# Case manifest
# ---------------------------------------------------------------------------


class CaseManifest(BaseModel):
    """Ground-truth manifest for a single benchmark corpus case.

    Constraints:
    - ``seeded_gaps`` may be empty only for ``hardened`` variants.
    - ``expected_line`` must be positive for every gap.
    - ``control_id`` values are validated against the active catalogue by
      ``validate_manifest_against_catalogue``.
    """

    format: PipelineFormat
    variant: str = Field(..., pattern=r"^(insecure|partial|hardened)$")
    description: str = ""
    seeded_gaps: list[SeedGap] = Field(default_factory=list)
    unassessable_fragments: list[UnassessableFragment] = Field(default_factory=list)

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _non_hardened_must_have_gaps(self) -> "CaseManifest":
        if self.variant in ("insecure", "partial") and not self.seeded_gaps:
            raise ValueError(
                f"Variant '{self.variant}' must declare at least one seeded_gap."
            )
        return self

    @field_validator("seeded_gaps", mode="after")
    @classmethod
    def _no_duplicate_gap_ids(cls, gaps: list[SeedGap]) -> list[SeedGap]:
        """(control_id, expected_line) pairs must be unique within a case."""
        seen: set[tuple[str, int]] = set()
        for gap in gaps:
            key = (gap.control_id, gap.expected_line)
            if key in seen:
                raise ValueError(
                    f"Duplicate (control_id, expected_line): "
                    f"control_id={gap.control_id!r} line={gap.expected_line}"
                )
            seen.add(key)
        return gaps


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ManifestValidationError(ValueError):
    """Raised when a manifest fails schema or catalogue validation.

    Carries ``case_path`` for precise error reporting.
    """

    def __init__(self, message: str, case_path: str = "", field: str = "") -> None:
        super().__init__(message)
        self.case_path = case_path
        self.field = field


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------


def load_manifest(manifest_path: Path) -> CaseManifest:
    """Load and validate a ``ground_truth.yaml`` manifest file.

    Args:
        manifest_path: Absolute or relative path to the ground_truth.yaml.

    Returns:
        Validated ``CaseManifest`` instance.

    Raises:
        ManifestValidationError: If the file is missing, unparseable, or fails
            Pydantic validation.
    """
    if not manifest_path.exists():
        raise ManifestValidationError(
            f"Manifest file not found: {manifest_path}",
            case_path=str(manifest_path),
        )
    try:
        raw: Any = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ManifestValidationError(
            f"YAML parse error in manifest {manifest_path}: {exc}",
            case_path=str(manifest_path),
        ) from exc

    if not isinstance(raw, dict):
        raise ManifestValidationError(
            f"Manifest must be a YAML mapping; got {type(raw).__name__}",
            case_path=str(manifest_path),
        )

    from pydantic import ValidationError

    try:
        return CaseManifest.model_validate(raw)
    except ValidationError as exc:
        raise ManifestValidationError(
            f"Manifest schema validation failed for {manifest_path}: {exc}",
            case_path=str(manifest_path),
        ) from exc


def validate_manifest_against_catalogue(
    manifest: CaseManifest,
    catalogue: CatalogueSnapshot,
    case_path: str = "",
) -> None:
    """Validate all ``control_id`` values against the active catalogue.

    Fails loudly if any control_id is unknown so that stale manifests never
    silently score as misses.

    Args:
        manifest: The manifest to validate.
        catalogue: The active catalogue snapshot to check against.
        case_path: Human-readable path label for error messages.

    Raises:
        ManifestValidationError: If any control_id is absent from the catalogue.
    """
    known_ids: set[str] = {
        ctrl.id
        for cat in catalogue.categories
        for ctrl in cat.controls
    }
    unknown = [
        gap.control_id
        for gap in manifest.seeded_gaps
        if gap.control_id not in known_ids
    ]
    if unknown:
        raise ManifestValidationError(
            f"Unknown control_id(s) {unknown!r} in manifest for {case_path!r}; "
            f"known IDs: {sorted(known_ids)!r}",
            case_path=case_path,
            field="control_id",
        )


# ---------------------------------------------------------------------------
# Corpus discovery
# ---------------------------------------------------------------------------

#: Name of the definition files by format.
DEFINITION_FILENAME: dict[PipelineFormat, str] = {
    PipelineFormat.GITHUB_ACTIONS: "definition.yml",
    PipelineFormat.GITLAB_CI: "definition.yml",
    PipelineFormat.JENKINS: "definition.groovy",
}


def load_corpus_manifests(
    corpus_root: Path,
    catalogue: CatalogueSnapshot,
) -> list[tuple[Path, CaseManifest]]:
    """Discover and validate all corpus cases under ``corpus_root``.

    Traverses ``<corpus_root>/<format>/<case-name>/`` directories.  Each must
    contain a ``ground_truth.yaml``.

    Args:
        corpus_root: Root of the corpus directory tree.
        catalogue: Active catalogue for control_id validation.

    Returns:
        Ordered list of ``(case_dir, manifest)`` pairs.

    Raises:
        ManifestValidationError: If the corpus is empty or any manifest fails.
    """
    if not corpus_root.is_dir():
        raise ManifestValidationError(
            f"Corpus root is not a directory: {corpus_root}",
            case_path=str(corpus_root),
        )

    cases: list[tuple[Path, CaseManifest]] = []
    for format_dir in sorted(corpus_root.iterdir()):
        if not format_dir.is_dir():
            continue
        for case_dir in sorted(format_dir.iterdir()):
            if not case_dir.is_dir():
                continue
            manifest_path = case_dir / "ground_truth.yaml"
            manifest = load_manifest(manifest_path)
            validate_manifest_against_catalogue(
                manifest, catalogue, case_path=str(case_dir)
            )
            cases.append((case_dir, manifest))

    if not cases:
        raise ManifestValidationError(
            f"Corpus directory is empty — no cases found under {corpus_root}. "
            "An empty corpus must not report a vacuous 100% detection rate.",
            case_path=str(corpus_root),
        )

    return cases
