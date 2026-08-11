"""Read-only benchmark Trust panel API endpoint.

Provides a single GET endpoint that returns the latest benchmark run summary
so the dashboard Trust panel can display it.  The JSON artefact is written by
``python -m pipelineshield.benchmark.gate`` (the CLI) and read here; no write
path exists from the UI.

Endpoint:
    GET /benchmark/latest   → 200 BenchmarkRun JSON | 404 if no run exists

Access:
    Requires GOVERNANCE_READ capability (devsecops_engineer, appsec_lead).
    app_developer, engineering_manager, devops_engineer are denied 403.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status

from ...authz.capabilities import Capability
from ...authz.guard import require_capability
from ...benchmark.matcher import BenchmarkRun

router = APIRouter(
    prefix="/benchmark",
    tags=["benchmark"],
)

_REQUIRE_READ = Depends(require_capability(Capability.GOVERNANCE_READ))

# Default artefact path — can be overridden via BENCHMARK_RESULTS_DIR env var.
_DEFAULT_RESULTS_DIR = Path("benchmark-results")


def _results_dir() -> Path:
    env = os.environ.get("BENCHMARK_RESULTS_DIR")
    return Path(env) if env else _DEFAULT_RESULTS_DIR


@router.get(
    "/latest",
    response_model=BenchmarkRun,
    summary="Latest benchmark run summary",
    description=(
        "Returns the most recent detection-rate benchmark run artefact. "
        "Written by the CI gate runner; no write path exists from this API. "
        "Returns 404 when no run has been performed yet."
    ),
    responses={
        200: {"description": "Latest benchmark run"},
        404: {"description": "No benchmark run artefact found"},
        403: {"description": "Insufficient capability"},
    },
)
def get_latest_benchmark(
    _actor: object = _REQUIRE_READ,
) -> BenchmarkRun:
    """Return the latest benchmark run from the artefact directory."""
    latest_path = _results_dir() / "latest.json"
    if not latest_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No benchmark run artefact found. "
                "Run 'python -m pipelineshield.benchmark.gate' to generate one."
            ),
        )
    try:
        payload = json.loads(latest_path.read_text(encoding="utf-8"))
        return BenchmarkRun.model_validate(payload)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not parse benchmark artefact: {exc}",
        ) from exc
