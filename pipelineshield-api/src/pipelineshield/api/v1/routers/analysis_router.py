"""Analysis ingestion router — POST /api/v1/analyses.

Accepts both application/json (paste) and multipart/form-data (upload).
Content-type dispatch is done via the incoming ``Content-Type`` header.

The router is thin — no SQL and no role branching.  All business logic
lives in ``AnalysisOrchestrator``.  Errors are mapped to RFC 7807 bodies.
"""
from __future__ import annotations

import logging
import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from pipelineshield.api.security.authz_guard import CurrentActor, require_capability
from pipelineshield.api.v1.schemas.analysis import (
    AnalysisResponse,
    IngestionErrorResponse,
    PAYLOAD_MAX_BYTES,
    PasteAnalysisRequest,
    PipelineFormat,
)
from pipelineshield.crypto.key_provider import EnvKeyProvider
from pipelineshield.services.analysis_orchestrator import (
    AnalysisOrchestrator,
    EmptyContentError,
    IngestionError,
    NoCatalogueError,
    PayloadTooLargeError,
    UnsupportedContentTypeError,
    YamlParseError,
)

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/analyses", tags=["analyses"])

_ALLOWED_PASTE_TYPES = frozenset({
    "application/json",
    "text/plain",
    "text/yaml",
    "application/x-yaml",
})

# ---------------------------------------------------------------------------
# Dependency: database session (overridden in tests)
# ---------------------------------------------------------------------------


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("get_db must be overridden before use")


# ---------------------------------------------------------------------------
# Dependency: orchestrator (overridden in tests to inject fake key provider)
# ---------------------------------------------------------------------------


def get_orchestrator() -> AnalysisOrchestrator:  # pragma: no cover
    """Build an AnalysisOrchestrator using the environment key provider.

    Override via app.dependency_overrides in tests.
    """
    return AnalysisOrchestrator(key_provider=EnvKeyProvider())


# ---------------------------------------------------------------------------
# RFC 7807 error builder
# ---------------------------------------------------------------------------


def _error_body(
    correlation_id: str,
    status: int,
    title: str,
    detail: str,
    constraint: str | None = None,
    parse_line: int | None = None,
    parse_column: int | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": f"https://pipelineshield.internal/errors/{title.lower().replace(' ', '-')}",
        "title": title,
        "status": status,
        "detail": detail,
        "correlation_id": correlation_id,
    }
    if constraint is not None:
        body["constraint"] = constraint
    if parse_line is not None:
        body["parse_line"] = parse_line
    if parse_column is not None:
        body["parse_column"] = parse_column
    body["errors"] = errors or []
    return body


# ---------------------------------------------------------------------------
# POST /api/v1/analyses
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a pipeline definition for security analysis",
    responses={
        400: {"model": IngestionErrorResponse},
        401: {"model": IngestionErrorResponse},
        403: {"model": IngestionErrorResponse},
        413: {"model": IngestionErrorResponse},
        415: {"model": IngestionErrorResponse},
        422: {"model": IngestionErrorResponse},
        503: {"model": IngestionErrorResponse},
    },
)
async def create_analysis(
    request: Request,
    actor: Annotated[CurrentActor, Depends(require_capability("analysis:create"))],
    session: Session = Depends(get_db),
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
) -> AnalysisResponse:
    """Accept a pipeline definition and return the created analysis.

    Supports two submission modes based on ``Content-Type``:
    - ``application/json`` — body is a PasteAnalysisRequest JSON object.
    - ``multipart/form-data`` — body contains a single file part plus an
      optional ``declared_format`` field.

    Returns 201 with the created analysis on success.
    """
    correlation_id = secrets.token_hex(16)

    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()

    try:
        if content_type == "multipart/form-data":
            definition_text, filename, declared_format_str = await _parse_upload(
                request, correlation_id
            )
        elif content_type in _ALLOWED_PASTE_TYPES or content_type == "":
            definition_text, filename, declared_format_str = await _parse_paste(
                request, correlation_id
            )
        else:
            raise UnsupportedContentTypeError(content_type)

        return orchestrator.ingest(
            session=session,
            actor=actor,
            definition_text=definition_text,
            filename=filename,
            declared_format=declared_format_str,
            correlation_id=correlation_id,
        )

    except PayloadTooLargeError as exc:
        raise HTTPException(
            status_code=413,
            detail=_error_body(
                correlation_id, 413, "Payload Too Large", str(exc),
                constraint=exc.constraint,
            ),
        ) from exc

    except EmptyContentError as exc:
        raise HTTPException(
            status_code=400,
            detail=_error_body(
                correlation_id, 400, "Empty Content", str(exc),
                constraint=exc.constraint,
            ),
        ) from exc

    except UnsupportedContentTypeError as exc:
        raise HTTPException(
            status_code=415,
            detail=_error_body(
                correlation_id, 415, "Unsupported Media Type", str(exc),
                constraint=exc.constraint,
            ),
        ) from exc

    except YamlParseError as exc:
        raise HTTPException(
            status_code=422,
            detail=_error_body(
                correlation_id, 422, "Unprocessable Definition", str(exc),
                constraint=exc.constraint,
                parse_line=exc.parse_line,
                parse_column=exc.parse_column,
            ),
        ) from exc

    except NoCatalogueError as exc:
        raise HTTPException(
            status_code=503,
            detail=_error_body(
                correlation_id, 503, "Service Unavailable", str(exc),
                constraint=exc.constraint,
            ),
        ) from exc

    except IngestionError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=_error_body(
                correlation_id, exc.status_code, "Ingestion Error", str(exc),
                constraint=exc.constraint,
            ),
        ) from exc

    except Exception as exc:
        _LOG.error(
            "analysis_ingestion_unhandled_error",
            extra={
                "correlation_id": correlation_id,
                "actor_id": str(actor.user_id),
                "error_type": type(exc).__name__,
            },
            exc_info=False,
        )
        raise HTTPException(
            status_code=500,
            detail=_error_body(
                correlation_id, 500, "Internal Server Error",
                "An unexpected error occurred. Please retry with the correlation id.",
            ),
        ) from exc


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


async def _parse_paste(
    request: Request,
    correlation_id: str,
) -> tuple[str, str | None, str | None]:
    """Parse a JSON paste request body into (definition_text, filename, format)."""
    try:
        raw = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=_error_body(
                correlation_id, 400, "Malformed Request",
                "Request body is not valid JSON.",
            ),
        ) from exc

    try:
        parsed = PasteAnalysisRequest.model_validate(raw)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=_error_body(
                correlation_id, 422, "Validation Error",
                f"Request body failed validation: {exc}",
            ),
        ) from exc

    declared = parsed.declared_format.value if parsed.declared_format else None
    return parsed.definition_text, parsed.filename, declared


async def _parse_upload(
    request: Request,
    correlation_id: str,
) -> tuple[str, str | None, str | None]:
    """Parse a multipart upload request into (definition_text, filename, format)."""
    try:
        form = await request.form()
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=_error_body(
                correlation_id, 400, "Malformed Request",
                "Could not parse multipart form data.",
            ),
        ) from exc

    # Locate the file part
    file_field = None
    for key, value in form.multi_items():
        if isinstance(value, UploadFile):
            file_field = value
            break

    if file_field is None:
        raise HTTPException(
            status_code=400,
            detail=_error_body(
                correlation_id, 400, "Missing File",
                "Multipart request must contain exactly one file part.",
                constraint="multipart_file_required",
            ),
        )

    raw_bytes = await file_field.read()
    if len(raw_bytes) > PAYLOAD_MAX_BYTES:
        raise PayloadTooLargeError(len(raw_bytes))

    try:
        definition_text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        definition_text = raw_bytes.decode("latin-1")

    filename = file_field.filename or None

    declared_str = form.get("declared_format")
    if isinstance(declared_str, UploadFile):
        declared_str = None
    declared_format_str: str | None = str(declared_str) if declared_str else None

    return definition_text, filename, declared_format_str
