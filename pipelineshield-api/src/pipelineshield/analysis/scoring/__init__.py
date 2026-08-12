"""Deterministic scoring engine for pipeline security analysis.

Exports the public contract consumed by the orchestrator and persistence layer:
- ScoringEngine (engine.py)
- ControlVerdict, CategoryScore, ScoreResult (models.py)
- CatalogueLoader (catalogue.py)
"""
from .models import CategoryScore, ControlVerdict, ScoreResult, Verdict
from .engine import ScoringEngine, ScoringError
from .catalogue import CatalogueLoader, CatalogueView

__all__ = [
    "CategoryScore",
    "ControlVerdict",
    "ScoreResult",
    "Verdict",
    "ScoringEngine",
    "ScoringError",
    "CatalogueLoader",
    "CatalogueView",
]
