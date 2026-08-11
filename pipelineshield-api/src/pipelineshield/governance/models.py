"""Pydantic v2 request and response models for the governance API.

All response models use response_model_exclude_unset=False so undeclared
fields cannot leak through the FastAPI serializer.  All timestamps are
serialized as ISO 8601 strings with UTC timezone.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Shared pagination envelope
# ---------------------------------------------------------------------------


class PaginatedResponse(BaseModel):
    """Cursor-paginated response envelope."""

    items: list[Any]
    next_cursor: str | None = None
    has_more: bool = False


# ---------------------------------------------------------------------------
# Classification inventory
# ---------------------------------------------------------------------------


class ClassificationEntryResponse(BaseModel):
    """One entity classification record."""

    name: str
    tier: str
    retention: str
    encryption: str
    masking_rule: str
    access_rule: str


class ClassificationInventoryResponse(BaseModel):
    """GET /governance/classification-inventory response."""

    entities: list[ClassificationEntryResponse]


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


class AuditEventItem(BaseModel):
    """Single audit event in the paginated list."""

    id: uuid.UUID
    occurred_at: datetime
    actor_id: str
    actor_display: str | None = None
    actor_persona: str | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    workspace_id: str | None = None
    change_detail: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None


class AuditEventListResponse(BaseModel):
    """GET /governance/audit-events response."""

    items: list[AuditEventItem]
    next_cursor: str | None = None
    has_more: bool = False


# ---------------------------------------------------------------------------
# Purge receipts
# ---------------------------------------------------------------------------


class PurgeReceiptItem(BaseModel):
    """Single purge receipt in the paginated list."""

    id: uuid.UUID
    batch_id: uuid.UUID
    executed_at: datetime
    entity_counts: dict[str, int] = Field(default_factory=dict)
    verification_digest: str
    status: str = "completed"
    error_detail: str | None = None


class PurgeReceiptListResponse(BaseModel):
    """GET /governance/purge-receipts response."""

    items: list[PurgeReceiptItem]
    next_cursor: str | None = None
    has_more: bool = False


# ---------------------------------------------------------------------------
# Retention policy
# ---------------------------------------------------------------------------


class RetentionPolicyResponse(BaseModel):
    """GET /governance/retention-policy response."""

    retention_days: int
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    last_run_status: str | None = None
    purge_sla_breaches: int = 0
    updated_by: str
    updated_at: datetime


class RetentionPolicyUpdateRequest(BaseModel):
    """PUT /governance/retention-policy request body."""

    retention_days: int = Field(..., ge=1, le=90)

    @field_validator("retention_days")
    @classmethod
    def validate_max_policy(cls, v: int) -> int:
        if v > 90:
            raise ValueError(
                f"retention_days={v} exceeds the 90-day maximum policy for "
                "Confidential entities.  Values above 90 are not permitted."
            )
        return v


# ---------------------------------------------------------------------------
# Export history
# ---------------------------------------------------------------------------


class ExportHistoryItem(BaseModel):
    """Single export history entry."""

    id: uuid.UUID
    occurred_at: datetime
    actor_id: str
    actor_display: str | None = None
    resource_type: str
    resource_id: str | None = None
    format: str | None = None


class ExportHistoryListResponse(BaseModel):
    """GET /governance/export-history response."""

    items: list[ExportHistoryItem]
    next_cursor: str | None = None
    has_more: bool = False


# ---------------------------------------------------------------------------
# Error
# ---------------------------------------------------------------------------


class ProblemDetail(BaseModel):
    """RFC 7807 problem+json error body."""

    type: str
    title: str
    status: int
    detail: str
    instance: str | None = None
