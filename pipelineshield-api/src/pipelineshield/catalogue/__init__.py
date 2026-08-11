"""Catalogue domain — versioned immutable control catalogue.

Exports:
- Pydantic schemas (CatalogueSnapshot, ControlCategory, ControlDefinition, GradeBand)
- Canonical JSON serialisation and SHA-256 checksum helpers
- CatalogueValidationError, CatalogueVersionConflictError
"""
from .schemas import (
    CatalogueSnapshot,
    ControlCategory,
    ControlDefinition,
    GradeBand,
    Severity,
    CatalogueValidationError,
    CatalogueVersionConflictError,
)
from .checksum import canonical_json, compute_checksum

__all__ = [
    "CatalogueSnapshot",
    "ControlCategory",
    "ControlDefinition",
    "GradeBand",
    "Severity",
    "CatalogueValidationError",
    "CatalogueVersionConflictError",
    "canonical_json",
    "compute_checksum",
]
