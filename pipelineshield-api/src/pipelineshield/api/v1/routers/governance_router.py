"""Governance router — subject data export and erasure.

POST /api/v1/governance/subjects/{user_id}/export
    Returns a masked JSON bundle of all data stored about the subject.
    Requires governance:data capability.

POST /api/v1/governance/subjects/{user_id}/erasure
    Immediately hard-deletes the subject's Confidential material using the
    shared purge primitive.  Requires governance:data capability and an
    explicit confirm=true in the request body.

Out of scope (PRD Assumption A7, pending ratification):
    - DSAR case management
    - Data rectification
    - Portability formats beyond JSON

Status codes:
  200  success (export or erasure)
  400  missing/false confirm field
  403  non-governance persona (app_developer, devops_engineer, engineering_manager)
  404  unknown or cross-workspace subject (existence not disclosed)
  500  partial erasure failure (receipt written, correlation_id only in response)
"""
from __future__ import annotations

import secrets
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from pipelineshield.api.security.authz_guard import CurrentActor, require_capability
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.services.subject_rights_service import (
    ConfirmationRequiredError,
    ErasureReceipt,
    SubjectBundle,
    SubjectNotFoundError,
    SubjectRightsService,
)

router = APIRouter(prefix="/governance", tags=["governance"])

_service = SubjectRightsService()


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("get_db must be overridden before use")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SubjectBundleResponse(BaseModel):
    bundle_version: str
    generated_at: str
    subject: dict[str, Any]
    role_bindings: list[dict[str, Any]]
    definitions: list[dict[str, Any]]
    analyses: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    remediations: list[dict[str, Any]]
    generated_drafts: list[dict[str, Any]]
    audit_trail: list[dict[str, Any]]


class ErasureRequest(BaseModel):
    confirm: bool
    reason: str = ""

    @field_validator("confirm")
    @classmethod
    def confirm_must_be_true(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "confirm must be true to proceed with erasure. "
                "This operation is irreversible."
            )
        return v


class ErasureResponse(BaseModel):
    batch_id: str
    executed_at: str
    entity_counts: dict[str, int]
    verification_digest: str
    status: str
    subject_user_id: str


class ErrorResponse(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    correlation_id: str | None = None
    errors: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# POST /api/v1/governance/subjects/{user_id}/export
# ---------------------------------------------------------------------------


@router.post(
    "/subjects/{user_id}/export",
    response_model=SubjectBundleResponse,
    summary="Export all data stored about a data subject (governance only)",
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
async def export_subject(
    user_id: uuid.UUID,
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    request: Request,
    session: Session = Depends(get_db),
) -> SubjectBundleResponse:
    corr = request.headers.get("x-correlation-id") or secrets.token_hex(8)
    audit = AuditWriter(session)
    try:
        bundle = _service.export_subject_data(
            session,
            user_id=user_id,
            workspace_id=actor.workspace_id,
            actor_id=str(actor.user_id),
            audit_writer=audit,
            correlation_id=corr,
        )
    except SubjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": "The requested subject was not found.",
                "correlation_id": corr,
                "errors": [],
            },
        ) from exc

    return SubjectBundleResponse(
        bundle_version=bundle.bundle_version,
        generated_at=bundle.generated_at,
        subject=bundle.subject,
        role_bindings=bundle.role_bindings,
        definitions=bundle.definitions,
        analyses=bundle.analyses,
        findings=bundle.findings,
        remediations=bundle.remediations,
        generated_drafts=bundle.generated_drafts,
        audit_trail=bundle.audit_trail,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/governance/subjects/{user_id}/erasure
# ---------------------------------------------------------------------------


@router.post(
    "/subjects/{user_id}/erasure",
    response_model=ErasureResponse,
    summary="Erase a data subject's Confidential material (governance only)",
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def erase_subject(
    user_id: uuid.UUID,
    body: ErasureRequest,
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    request: Request,
    session: Session = Depends(get_db),
) -> ErasureResponse:
    corr = request.headers.get("x-correlation-id") or secrets.token_hex(8)
    audit = AuditWriter(session)
    try:
        receipt = _service.erase_subject_data(
            session,
            user_id=user_id,
            workspace_id=actor.workspace_id,
            actor_id=str(actor.user_id),
            confirm=body.confirm,
            reason=body.reason,
            audit_writer=audit,
            correlation_id=corr,
        )
    except ConfirmationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "type": "https://pipelineshield.internal/errors/validation",
                "title": "Confirmation Required",
                "status": 400,
                "detail": str(exc),
                "correlation_id": corr,
                "errors": [{"field": "confirm", "message": str(exc)}],
            },
        ) from exc
    except SubjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": "The requested subject was not found.",
                "correlation_id": corr,
                "errors": [],
            },
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "type": "https://pipelineshield.internal/errors/erasure-failed",
                "title": "Erasure Failed",
                "status": 500,
                "detail": "Erasure completed with verification failure. See audit log.",
                "correlation_id": corr,
                "errors": [],
            },
        ) from exc

    return ErasureResponse(
        batch_id=str(receipt.batch_id),
        executed_at=receipt.executed_at,
        entity_counts=receipt.entity_counts,
        verification_digest=receipt.verification_digest,
        status=receipt.status,
        subject_user_id=receipt.subject_user_id,
    )
