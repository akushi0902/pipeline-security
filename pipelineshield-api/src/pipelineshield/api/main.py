"""FastAPI application factory for PipelineShield API.

The app is created via ``create_app()`` so that tests can override
dependencies (session, current actor) without mutating global state.
"""
from __future__ import annotations

from fastapi import FastAPI

from pipelineshield.api.v1.routers.catalogue_router import router as catalogue_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="PipelineShield API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    app.include_router(catalogue_router, prefix="/api/v1")

    return app


app = create_app()
