"""FastAPI router for the governance console API.

Six endpoints, all guarded by AuthzGuard requiring governance capability.
No business logic or SQL lives here — all delegation is to GovernanceService.

Endpoint map:
    GET  /governance/classification-inventory  → governance:read
    GET  /governance/audit-events              → governance:read
    GET  /governance/retention-policy          → governance:read
    PUT  /governance/retention-policy          → governance:write
    GET  /governance/purge-receipts            → governance:read
    GET  /governance/export-history            → governance:read

Every error returns problem+json (media type application/problem+json).
Unauthorized requests return 403; cross-workspace resources return 404.
Invalid cursors return 400 with actionable detail.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..authz.capabilities import Capability
from ..authz.guard import ActorContext, require_capability
from ..governance.cursor import CursorError
from ..governance.models import (
    AuditEventListResponse,
    ClassificationInventoryResponse,
    ExportHistoryListResponse,
    ProblemDetail,
    PurgeReceiptListResponse,
    RetentionPolicyResponse,
    RetentionPolicyUpdateRequest,
)
from ..governance.service import GovernanceService, GovernanceValidationError
from ..persistence.db import get_session
from ..persistence.repositories.audit import SQLAlchemyAuditRepository
from ..persistence.repositories.governance import GovernanceRepository

router = APIRouter(
    prefix="/governance",
    tags=["governance"],
)

_REQUIRE_READ = Depends(require_capability(Capability.GOVERNANCE_READ))
_REQUIRE_WRITE = Depends(require_capability(Capability.GOVERNANCE_WRITE))


def _make_service(session: Session = Depends(get_session)) -> GovernanceService:
    return GovernanceService(
        governance_repo=GovernanceRepository(session),
        audit_repo=SQLAlchemyAuditRepository(session),
    )


def _cursor_error_response(detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        media_type="application/problem+json",
        content={
            "type": "invalid_cursor",
            "title": "Invalid Pagination Cursor",
            "status": 400,
            "detail": detail,
        },
    )


# ---------------------------------------------------------------------------
# GET /governance/classification-inventory
# ---------------------------------------------------------------------------


@router.get(
    "/classification-inventory",
    response_model=ClassificationInventoryResponse,
    summary="Entity classification inventory",
    description=(
        "Returns the static entity classification inventory for SOC 2 review. "
        "Lists every data entity with its tier, retention period, encryption "
        "method, masking rule and access policy."
    ),
)
def get_classification_inventory(
    actor: ActorContext = _REQUIRE_READ,
    service: GovernanceService = Depends(_make_service),
) -> ClassificationInventoryResponse:
    return service.get_classification_inventory()


# ---------------------------------------------------------------------------
# GET /governance/audit-events
# ---------------------------------------------------------------------------


@router.get(
    "/audit-events",
    response_model=AuditEventListResponse,
    summary="Append-only audit event log (cursor-paginated)",
    description=(
        "Returns a cursor-paginated, filterable view of the append-only audit log. "
        "Records are immutable — this endpoint exposes no write affordance at any "
        "privilege level.  Default page size 50, maximum 200."
    ),
)
def list_audit_events(
    request: Request,
    actor: ActorContext = _REQUIRE_READ,
    service: GovernanceService = Depends(_make_service),
    cursor: Annotated[str | None, Query(description="Opaque pagination cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=200, description="Page size (max 200)")] = 50,
    actor_id: Annotated[str | None, Query()] = None,
    action: Annotated[str | None, Query()] = None,
    resource_type: Annotated[str | None, Query()] = None,
    from_: Annotated[
        datetime | None, Query(alias="from", description="Start of time range (ISO 8601)")
    ] = None,
    to: Annotated[
        datetime | None, Query(description="End of time range (ISO 8601)")
    ] = None,
) -> AuditEventListResponse:
    try:
        return service.list_audit_events(
            actor=actor,
            limit=limit,
            cursor=cursor,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            from_dt=from_,
            to_dt=to,
        )
    except CursorError as exc:
        return _cursor_error_response(str(exc))  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# GET /governance/retention-policy
# ---------------------------------------------------------------------------


@router.get(
    "/retention-policy",
    response_model=RetentionPolicyResponse,
    summary="Current retention policy",
    description=(
        "Returns the active retention configuration including the configured "
        "period, next scheduled purge run, last run outcome and SLA breach count."
    ),
)
def get_retention_policy(
    actor: ActorContext = _REQUIRE_READ,
    service: GovernanceService = Depends(_make_service),
) -> RetentionPolicyResponse:
    return service.get_retention_policy()


# ---------------------------------------------------------------------------
# PUT /governance/retention-policy
# ---------------------------------------------------------------------------


@router.put(
    "/retention-policy",
    response_model=RetentionPolicyResponse,
    summary="Update retention policy",
    description=(
        "Updates the retention period.  Validates against the 90-day maximum for "
        "Confidential entities and emits exactly one audit_event recording the "
        "before and after values.  Requires governance:write capability."
    ),
)
def update_retention_policy(
    body: RetentionPolicyUpdateRequest,
    actor: ActorContext = _REQUIRE_WRITE,
    service: GovernanceService = Depends(_make_service),
) -> RetentionPolicyResponse:
    try:
        return service.update_retention_policy(body, actor)
    except GovernanceValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "type": "retention_policy_violation",
                "title": "Retention Policy Violation",
                "status": 400,
                "detail": str(exc),
            },
        )


# ---------------------------------------------------------------------------
# GET /governance/purge-receipts
# ---------------------------------------------------------------------------


@router.get(
    "/purge-receipts",
    response_model=PurgeReceiptListResponse,
    summary="Purge receipt history (cursor-paginated)",
    description=(
        "Returns a cursor-paginated list of purge receipts.  Failed receipts "
        "are visually distinguished via status='failed' and include error_detail."
    ),
)
def list_purge_receipts(
    actor: ActorContext = _REQUIRE_READ,
    service: GovernanceService = Depends(_make_service),
    cursor: Annotated[str | None, Query(description="Opaque pagination cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> PurgeReceiptListResponse:
    try:
        return service.list_purge_receipts(limit=limit, cursor=cursor)
    except CursorError as exc:
        return _cursor_error_response(str(exc))  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# GET /governance/export-history
# ---------------------------------------------------------------------------


@router.get(
    "/export-history",
    response_model=ExportHistoryListResponse,
    summary="Export history (cursor-paginated)",
    description=(
        "Returns a cursor-paginated list of export events derived from the "
        "audit log (action=export.create).  Provides actor, timestamp, resource "
        "and format for SOC 2 evidence gathering."
    ),
)
def list_export_history(
    actor: ActorContext = _REQUIRE_READ,
    service: GovernanceService = Depends(_make_service),
    cursor: Annotated[str | None, Query(description="Opaque pagination cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ExportHistoryListResponse:
    try:
        return service.list_export_history(limit=limit, cursor=cursor)
    except CursorError as exc:
        return _cursor_error_response(str(exc))  # type: ignore[return-value]
