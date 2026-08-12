"""Entity classification inventory — static registry of data classifications.

Derived from the architecture data-classification table committed to the
baseline Alembic migration.  This registry is the source of truth for the
GET /governance/classification-inventory endpoint.

Each entity record is immutable: the classification tier, retention period,
encryption method and access policy are set at design time and never mutated
at runtime.  Changes require a code review, migration update, and audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClassificationEntry:
    """One entity classification record."""

    name: str
    tier: str
    retention: str
    encryption: str
    masking_rule: str
    access_rule: str


# Static registry — matches the TABLE COMMENT annotations in migration 0001.
CLASSIFICATION_INVENTORY: tuple[ClassificationEntry, ...] = (
    ClassificationEntry(
        name="analysis",
        tier="Confidential",
        retention="90 days",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="All score fields masked in export; pipeline text excluded from audit log",
        access_rule="Governance, DevSecOps, AppSec Lead, DevOps Engineer, App Developer (own workspace)",
    ),
    ClassificationEntry(
        name="pipeline_definition",
        tier="Confidential",
        retention="90 days",
        encryption="AES-256-GCM envelope encryption (masked_content column)",
        masking_rule="Definition content never written to audit log; masked_content is ciphertext",
        access_rule="Governance, DevSecOps, AppSec Lead, DevOps Engineer, App Developer (own workspace)",
    ),
    ClassificationEntry(
        name="finding",
        tier="Confidential",
        retention="90 days",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="AI findings carry weight=0 and requires_human_review=true",
        access_rule="Governance, DevSecOps, AppSec Lead, DevOps Engineer, App Developer (own workspace)",
    ),
    ClassificationEntry(
        name="remediation",
        tier="Confidential",
        retention="90 days",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="Recommendation only; never auto-applied",
        access_rule="Governance, DevSecOps, AppSec Lead, DevOps Engineer, App Developer (own workspace)",
    ),
    ClassificationEntry(
        name="generated_draft",
        tier="Confidential",
        retention="90 days",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="Always requires human review; marked draft until accepted",
        access_rule="Governance, DevSecOps, AppSec Lead, DevOps Engineer (own workspace)",
    ),
    ClassificationEntry(
        name="audit_event",
        tier="Restricted",
        retention="1 year",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="change_detail must never contain definition content or secret values",
        access_rule="Governance, DevSecOps, AppSec Lead (INSERT+SELECT; no UPDATE/DELETE at DB level)",
    ),
    ClassificationEntry(
        name="purge_receipt",
        tier="Internal",
        retention="Indefinite (SOC 2 evidence)",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="No masking required; receipts contain only counts and digests",
        access_rule="Governance, DevSecOps, AppSec Lead",
    ),
    ClassificationEntry(
        name="retention_policy",
        tier="Internal",
        retention="Indefinite",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="No masking required",
        access_rule="Governance write (devsecops_engineer, appsec_lead); all governance read",
    ),
    ClassificationEntry(
        name="app_user",
        tier="Internal",
        retention="Indefinite",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="Email masked in export payloads; display_name retained for audit trail",
        access_rule="Own workspace administrators; governance read",
    ),
    ClassificationEntry(
        name="workspace",
        tier="Internal",
        retention="Indefinite",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="No masking required",
        access_rule="Own workspace administrators; governance read",
    ),
    ClassificationEntry(
        name="role_binding",
        tier="Internal",
        retention="Indefinite",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="No masking required",
        access_rule="Own workspace administrators; governance read",
    ),
    ClassificationEntry(
        name="control_catalogue_version",
        tier="Internal",
        retention="Indefinite (append-only versioned catalogue)",
        encryption="AES-256-GCM (at rest via storage encryption)",
        masking_rule="No masking required; catalogue is non-sensitive by design",
        access_rule="All authenticated users (read); only catalogue admin (write)",
    ),
)


def get_classification_inventory() -> tuple[ClassificationEntry, ...]:
    """Return the static classification inventory."""
    return CLASSIFICATION_INVENTORY
