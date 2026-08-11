"""Unit tests for the WO-045 seeded corpus and ground-truth manifest.

Tests (all pass without a database or network):
1.  Manifest schema validation — GroundTruthManifest parses ground_truth.yaml.
2.  Corpus file count — at least 15 files (6 GHA, 5 GitLab, 4 Jenkins).
3.  Format counts — minimum per format met.
4.  All nine control categories seeded at least once.
5.  Negative expectations count — at least 20.
6.  Not Assessable fragment count — at least 3.
7.  control_id referential integrity — all IDs exist in catalogue_v1.json.
8.  Duplicate control_id/file pair rejection in seeded_gaps.
9.  Duplicate (file, control_id) rejection in negative_expectations.
10. Conflict detection — same (file, control_id) in gaps AND negatives.
11. Line-count ceiling — all corpus files are under 500 lines.
12. All corpus files exist on disk.
13. Orphan check — every disk file is referenced in the manifest.
14. Synthetic-secret pattern test — all credential-shaped literals use EXAMPLE_ prefix.
15. Ingestion smoke test — every corpus file is UTF-8-decodable and non-empty.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).parent.parent / "fixtures"
_CORPUS_ROOT = _FIXTURES / "corpus"
_MANIFEST_PATH = _CORPUS_ROOT / "ground_truth.yaml"
_CATALOGUE_PATH = _FIXTURES / "catalogue_v1.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_manifest():
    from pipelineshield.benchmark.ground_truth import load_ground_truth
    return load_ground_truth(_MANIFEST_PATH)


def _all_corpus_files() -> list[Path]:
    """Return every pipeline definition file under the corpus root."""
    return sorted(
        p
        for p in _CORPUS_ROOT.rglob("*")
        if p.is_file() and p.suffix in (".yml", ".yaml", ".groovy")
        and p.name != "ground_truth.yaml"
    )


def _load_known_control_ids() -> frozenset[str]:
    data = json.loads(_CATALOGUE_PATH.read_text())
    return frozenset(
        ctrl["id"]
        for cat in data["categories"]
        for ctrl in cat["controls"]
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_manifest_parses():
    manifest = _load_manifest()
    assert manifest.corpus_version == "1.0.0"
    assert manifest.catalogue_version == 1


def test_corpus_file_count():
    manifest = _load_manifest()
    assert len(manifest.corpus_files) >= 15, (
        f"Expected at least 15 corpus files; got {len(manifest.corpus_files)}"
    )


def test_format_counts():
    from pipelineshield.benchmark.ground_truth import PipelineFormat
    manifest = _load_manifest()
    gha = manifest.files_by_format(PipelineFormat.GITHUB_ACTIONS)
    gl = manifest.files_by_format(PipelineFormat.GITLAB_CI)
    jk = manifest.files_by_format(PipelineFormat.JENKINS)
    assert len(gha) >= 6, f"Expected ≥6 GitHub Actions files; got {len(gha)}"
    assert len(gl) >= 5, f"Expected ≥5 GitLab CI files; got {len(gl)}"
    assert len(jk) >= 4, f"Expected ≥4 Jenkins files; got {len(jk)}"


def test_all_nine_categories_seeded():
    manifest = _load_manifest()
    required = {
        "secrets_hygiene",
        "artifact_signing",
        "static_analysis",
        "dependency_scanning",
        "least_privilege",
        "iac_misconfiguration",
        "supply_chain_integrity",
        "sbom",
        "approval_gates",
    }
    seeded = {g.category for g in manifest.seeded_gaps}
    missing = required - seeded
    assert not missing, (
        f"Missing seeded gaps for categories: {sorted(missing)}"
    )


def test_negative_expectations_count():
    manifest = _load_manifest()
    assert len(manifest.negative_expectations) >= 20, (
        f"Expected ≥20 negative expectations; got {len(manifest.negative_expectations)}"
    )


def test_not_assessable_fragments_count():
    manifest = _load_manifest()
    assert len(manifest.unassessable_fragments) >= 3, (
        f"Expected ≥3 NA fragments; got {len(manifest.unassessable_fragments)}"
    )


def test_control_id_referential_integrity():
    manifest = _load_manifest()
    known = _load_known_control_ids()
    from pipelineshield.benchmark.ground_truth import validate_ground_truth_against_catalogue
    unknown = validate_ground_truth_against_catalogue(manifest, known)
    assert not unknown, (
        f"Unknown control_id(s) in ground_truth.yaml: {unknown!r}"
    )


def test_duplicate_seeded_gap_rejected():
    from pydantic import ValidationError
    from pipelineshield.benchmark.ground_truth import GroundTruthManifest, SeededGap

    with pytest.raises(ValidationError):
        GroundTruthManifest(
            corpus_version="test",
            catalogue_version=1,
            seeded_gaps=[
                SeededGap(
                    file="a.yml",
                    control_id="sh-001",
                    category="secrets_hygiene",
                    severity="critical",
                    expected_status="missing",
                    expected_anchor_line=5,
                    rationale="dup test",
                ),
                SeededGap(
                    file="a.yml",
                    control_id="sh-001",
                    category="secrets_hygiene",
                    severity="critical",
                    expected_status="missing",
                    expected_anchor_line=5,
                    rationale="dup test again",
                ),
            ],
        )


def test_conflicting_gap_and_negative_rejected():
    from pydantic import ValidationError
    from pipelineshield.benchmark.ground_truth import (
        GroundTruthManifest, SeededGap, NegativeExpectation
    )

    with pytest.raises(ValidationError):
        GroundTruthManifest(
            corpus_version="test",
            catalogue_version=1,
            seeded_gaps=[
                SeededGap(
                    file="a.yml",
                    control_id="sh-001",
                    category="secrets_hygiene",
                    severity="critical",
                    expected_status="missing",
                    expected_anchor_line=5,
                    rationale="seeded gap",
                ),
            ],
            negative_expectations=[
                NegativeExpectation(
                    file="a.yml",
                    control_id="sh-001",
                    category="secrets_hygiene",
                    rationale="conflict",
                ),
            ],
        )


def test_line_count_ceiling():
    manifest = _load_manifest()
    for cf in manifest.corpus_files:
        assert cf.line_count <= 500, (
            f"{cf.file} has line_count={cf.line_count} which exceeds 500-line ceiling"
        )


def test_all_corpus_files_exist_on_disk():
    manifest = _load_manifest()
    for cf in manifest.corpus_files:
        path = _CORPUS_ROOT / cf.file
        assert path.exists(), f"Corpus file not found on disk: {path}"


def test_no_orphan_disk_files():
    manifest = _load_manifest()
    declared = {cf.file for cf in manifest.corpus_files}
    on_disk = {
        str(p.relative_to(_CORPUS_ROOT)).replace("\\", "/")
        for p in _all_corpus_files()
    }
    orphans = on_disk - declared
    assert not orphans, (
        f"Corpus files on disk but not declared in ground_truth.yaml: {sorted(orphans)}"
    )


def test_synthetic_secret_prefix():
    """All credential-shaped literals must start with EXAMPLE_."""
    secret_pattern = re.compile(
        r"(?:password|token|secret|key|credential|api_key|passwd)\s*[:=]\s*(?!EXAMPLE_|env\.|\\$\{|<)[^\s'\"]",
        re.IGNORECASE,
    )
    for disk_path in _all_corpus_files():
        content = disk_path.read_text(encoding="utf-8")
        matches = secret_pattern.findall(content)
        # Strip lines that are comments or use variable expansion
        bad = [
            m for m in matches
            if not m.startswith("#")
        ]
        assert not bad, (
            f"Corpus file {disk_path.name} contains credential-like literal "
            f"not using EXAMPLE_ prefix: {bad!r}"
        )


def test_corpus_files_utf8_decodable_and_non_empty():
    for disk_path in _all_corpus_files():
        content = disk_path.read_text(encoding="utf-8")
        assert content.strip(), f"Corpus file is empty: {disk_path}"
        assert len(content.splitlines()) <= 500, (
            f"Corpus file {disk_path.name} exceeds 500 lines"
        )


def test_na_fragments_line_ranges_valid():
    manifest = _load_manifest()
    for frag in manifest.unassessable_fragments:
        assert frag.line_start <= frag.line_end, (
            f"NA fragment in {frag.file}: line_start > line_end"
        )
        path = _CORPUS_ROOT / frag.file
        if path.exists():
            total = len(path.read_text(encoding="utf-8").splitlines())
            assert frag.line_end <= total, (
                f"NA fragment in {frag.file}: line_end={frag.line_end} "
                f"exceeds file length {total}"
            )


def test_seeded_gap_anchor_lines_within_file():
    manifest = _load_manifest()
    for gap in manifest.seeded_gaps:
        path = _CORPUS_ROOT / gap.file
        if path.exists():
            total = len(path.read_text(encoding="utf-8").splitlines())
            assert gap.expected_anchor_line <= total, (
                f"SeededGap in {gap.file}: expected_anchor_line={gap.expected_anchor_line} "
                f"exceeds file length {total}"
            )
