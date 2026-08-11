"""FastAPI application factory for PipelineShield API.

The app is created via ``create_app()`` so that tests can override
dependencies (session, current actor) without mutating global state.
"""
from __future__ import annotations

import secrets as _secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from pipelineshield.api.middleware.body_size_limit import BodySizeLimitMiddleware
from pipelineshield.api.security.scope import AuthorizationError, ResourceNotVisibleError
from pipelineshield.api.v1.routers.analysis_router import router as analysis_router
from pipelineshield.api.v1.routers.audit_router import router as audit_router
from pipelineshield.api.v1.routers.auth_router import router as auth_router
from pipelineshield.api.v1.routers.catalogue_router import router as catalogue_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="PipelineShield API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # Body-size middleware must be added before routers so it wraps all routes.
    app.add_middleware(BodySizeLimitMiddleware)

    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(catalogue_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(analysis_router, prefix="/api/v1")

    # RFC 7807 handler for AuthorizationError (403) — resource visible, verb forbidden.
    @app.exception_handler(AuthorizationError)
    async def _authz_error_handler(
        request: Request, exc: AuthorizationError
    ) -> JSONResponse:
        corr = _secrets.token_hex(16)
        return JSONResponse(
            status_code=403,
            content={
                "type": "https://pipelineshield.internal/errors/forbidden",
                "title": "Forbidden",
                "status": 403,
                "detail": str(exc),
                "correlation_id": corr,
                "required_capability": exc.required_capability,
                "errors": [],
            },
        )

    # RFC 7807 handler for ResourceNotVisibleError (404) — existence not disclosed.
    @app.exception_handler(ResourceNotVisibleError)
    async def _not_visible_handler(
        request: Request, exc: ResourceNotVisibleError
    ) -> JSONResponse:
        corr = _secrets.token_hex(16)
        return JSONResponse(
            status_code=404,
            content={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": f"The requested {exc.resource_type} was not found.",
                "correlation_id": corr,
                "errors": [],
            },
        )

    # RFC 7807 handler for unhandled 422 Pydantic validation errors
    @app.exception_handler(422)
    async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
        from fastapi.exceptions import RequestValidationError
        if isinstance(exc, RequestValidationError):
            corr = _secrets.token_hex(16)
            errors = exc.errors()
            return JSONResponse(
                status_code=422,
                content={
                    "type": "https://pipelineshield.internal/errors/validation-error",
                    "title": "Validation Error",
                    "status": 422,
                    "detail": "Request body failed schema validation.",
                    "correlation_id": corr,
                    "errors": [
                        {"field": ".".join(str(l) for l in e.get("loc", [])),
                         "message": e.get("msg", "")}
                        for e in errors
                    ],
                },
            )
        raise exc

    return app


app = create_app()
