"""Governance fixture factory — generates in-memory test data.

Provides 1000+ audit events spanning 13 months, several purge receipts
(including one failed batch), export history rows and a retention policy.
All data is synthetic; no real customer content is included.

Usage in tests:
    from tests.fixtures.governance.factory import (
        make_audit_events,
        make_purge_receipts,
        make_export_events,
        WORKSPACE_ID,
        GOVERNANCE_ACTOR,
        APP_DEV_ACTOR,
        ENG_MANAGER_ACTOR,
    )
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.purge_receipt import PurgeReceipt

# -------------------------------------------------------------------------
# Fixed UUIDs for deterministic tests
# -------------------------------------------------------------------------

WORKSPACE_ID = uuid.UUID("00000000-1111-2222-3333-444444444444")
GOVERNANCE_ACTOR = "gov-actor@example.com"
APP_DEV_ACTOR = "dev-actor@example.com"
ENG_MANAGER_ACTOR = "mgr-actor@example.com"
CROSS_WORKSPACE_ID = uuid.UUID("ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb")

# Event types used in the corpus
_ACTIONS = [
    "analysis.create",
    "analysis.delete",
    "finding.create",
    "definition.create",
    "definition.delete",
    "remediation.create",
    "auth.login",
    "auth.logout",
    "retention_policy.update",
    "export.create",
]

_RESOURCE_TYPES = [
    "analysis",
    "finding",
    "pipeline_definition",
    "remediation",
    "auth",
    "retention_policy",
]

_PERSONAS = [
    "devsecops_engineer",
    "appsec_lead",
    "devops_engineer",
    "app_developer",
    "engineering_manager",
]


def make_audit_events(count: int = 1050) -> list[AuditEvent]:
    """Generate *count* synthetic audit events spanning 13 months.

    Events are spaced ~9.4 hours apart to cover Jan 2025 – Feb 2026.
    The first event is at 2025-01-01T00:00:00Z; spacing is uniform.

    Args:
        count: Number of events to generate.  Minimum 1000 for AC12.

    Returns:
        List of unsaved AuditEvent instances in ascending occurred_at order.
    """
    start = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    # 13 months ≈ 395 days ≈ 9480 hours; step = hours / count
    step_hours = 9480 / count
    step = timedelta(hours=step_hours)

    events: list[AuditEvent] = []
    for i in range(count):
        occurred_at = start + step * i
        action = _ACTIONS[i % len(_ACTIONS)]
        resource_type = _RESOURCE_TYPES[i % len(_RESOURCE_TYPES)]
        persona = _PERSONAS[i % len(_PERSONAS)]
        actor = GOVERNANCE_ACTOR if i % 5 == 0 else f"user-{i % 20}@example.com"

        event = AuditEvent(
            id=uuid.UUID(int=i + 1),
            actor_id=actor,
            actor_persona=persona,
            occurred_at=occurred_at,
            resource_type=resource_type,
            resource_id=str(uuid.UUID(int=i + 100000)),
            action=action,
            change_detail={"synthetic": True, "seq": i},
            correlation_id=f"req-{i:06d}",
        )
        events.append(event)

    return events


def make_export_events(count: int = 15) -> list[AuditEvent]:
    """Generate export audit events (action=export.create)."""
    start = datetime(2025, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    step = timedelta(days=30)

    events: list[AuditEvent] = []
    for i in range(count):
        occurred_at = start + step * i
        fmt = ["json", "csv", "pdf"][i % 3]
        event = AuditEvent(
            id=uuid.UUID(int=2_000_000 + i),
            actor_id=GOVERNANCE_ACTOR,
            actor_persona="devsecops_engineer",
            occurred_at=occurred_at,
            resource_type="analysis",
            resource_id=str(uuid.UUID(int=3_000_000 + i)),
            action="export.create",
            change_detail={"format": fmt, "synthetic": True},
            correlation_id=f"export-{i:04d}",
        )
        events.append(event)

    return events


def make_purge_receipts() -> list[PurgeReceipt]:
    """Generate synthetic purge receipts including one failed batch."""
    receipts: list[PurgeReceipt] = []

    batches = [
        # (months_ago, deleted_counts, digest, is_failed)
        (12, {"analysis": 120, "finding": 840, "pipeline_definition": 120}, "sha256-aabbcc", False),
        (9, {"analysis": 95, "finding": 665, "pipeline_definition": 95}, "sha256-ddeeff", False),
        (6, {"analysis": 0, "finding": 0, "pipeline_definition": 0, "error": "Purge worker timeout"}, "FAILED", True),
        (3, {"analysis": 200, "finding": 1400, "pipeline_definition": 200}, "sha256-112233", False),
        (1, {"analysis": 88, "finding": 616, "pipeline_definition": 88}, "sha256-445566", False),
    ]

    base = datetime(2025, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
    for i, (months_ago, counts, digest, _) in enumerate(batches):
        executed_at = base + timedelta(days=30 * months_ago)
        receipts.append(
            PurgeReceipt(
                id=uuid.UUID(int=5_000_000 + i),
                batch_id=uuid.UUID(int=6_000_000 + i),
                executed_at=executed_at,
                deleted_counts=counts,
                verification_digest=digest,
            )
        )

    return receipts
