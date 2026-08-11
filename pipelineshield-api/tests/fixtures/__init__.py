"""Test fixture helpers for PipelineShield.

Provides cached loaders for the seeded benchmark corpus and the top-level
ground-truth manifest so WO-044 through WO-047 share one source of truth
without re-implementing discovery.

Usage:
    from tests.fixtures import load_corpus, load_ground_truth

    manifest = load_ground_truth()       # GroundTruthManifest
    corpus   = load_corpus()             # list[(Path, str)]
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_CORPUS_ROOT = Path(__file__).parent / "corpus"
_MANIFEST_PATH = _CORPUS_ROOT / "ground_truth.yaml"


@lru_cache(maxsize=1)
def load_ground_truth():
    """Load and cache the top-level ground-truth manifest.

    Returns:
        ``GroundTruthManifest`` — validated Pydantic v2 model.

    Raises:
        ``GroundTruthLoadError`` on missing file or schema violation.
    """
    from pipelineshield.benchmark.ground_truth import (
        GroundTruthLoadError,
        load_ground_truth as _load,
    )

    return _load(_MANIFEST_PATH)


@lru_cache(maxsize=1)
def load_corpus() -> list[tuple[Path, str]]:
    """Discover all corpus files referenced by the manifest.

    Returns:
        Ordered list of ``(absolute_path, relative_file_name)`` pairs,
        in the order they appear in the manifest's ``corpus_files`` list.

    The returned paths are guaranteed to exist (load_ground_truth() validates
    them against the manifest).
    """
    manifest = load_ground_truth()
    result: list[tuple[Path, str]] = []
    for cf in manifest.corpus_files:
        abs_path = _CORPUS_ROOT / cf.file
        if not abs_path.exists():
            raise FileNotFoundError(
                f"Corpus file referenced in ground_truth.yaml not found on disk: "
                f"{abs_path}"
            )
        result.append((abs_path, cf.file))
    return result


def corpus_root() -> Path:
    """Return the absolute path of the corpus root directory."""
    return _CORPUS_ROOT


def manifest_path() -> Path:
    """Return the absolute path of the ground_truth.yaml manifest."""
    return _MANIFEST_PATH
