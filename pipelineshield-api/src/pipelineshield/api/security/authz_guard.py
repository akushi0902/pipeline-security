"""Authorization guard — deny-by-default RBAC for FastAPI routes.

Every route declares a capability requirement via ``require_capability()``.
The guard evaluates the current actor's persona against the capability map.
An unmapped capability equals deny.  The client-side role-check is cosmetic
only; this guard is the authoritative enforcement point.

Personas and capabilities
-------------------------
catalogue:read  — all five personas
catalogue:write — devsecops_engineer, appsec_lead only

Authorization-denial events are logged (and in a later WO written to the
audit trail) so that unexpected denial spikes can be alerted on.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Annotated, Callable

import fastapi
from fastapi import Depends, HTTPException, Request

__all__ = [
    "CurrentActor",
    "PERSONA_CAPABILITIES",
    "get_current_actor",
    "require_capability",
]

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Actor model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CurrentActor:
    """Immutable snapshot of the authenticated user at the time of the request."""

    user_id: uuid.UUID
    persona: str
    workspace_id: uuid.UUID
    display_name: str


# ---------------------------------------------------------------------------
# Capability map
# ---------------------------------------------------------------------------

PERSONA_CAPABILITIES: dict[str, frozenset[str]] = {
    "app_developer": frozenset({"catalogue:read", "analysis:create"}),
    "devops_engineer": frozenset({"catalogue:read", "analysis:create"}),
    "devsecops_engineer": frozenset({
        "catalogue:read", "catalogue:write", "audit:read", "analysis:create",
    }),
    "appsec_lead": frozenset({
        "catalogue:read", "catalogue:write", "audit:read", "analysis:create",
    }),
    "engineering_manager": frozenset({"catalogue:read"}),
}


# ---------------------------------------------------------------------------
# Base actor dependency (stub — OIDC wired in a later WO)
# ---------------------------------------------------------------------------


async def get_current_actor() -> CurrentActor:  # pragma: no cover
    """Yield the authenticated actor for the current request.

    This stub always raises 401.  In the full implementation it will
    validate the session cookie, resolve the actor from Redis/DB, and
    return the CurrentActor.  Tests override this dependency via
    app.dependency_overrides.
    """
    raise HTTPException(
        status_code=401,
        detail={
            "type": "https://pipelineshield.internal/errors/unauthenticated",
            "title": "Not authenticated",
            "status": 401,
            "detail": "A valid session is required. Please sign in.",
        },
    )


# ---------------------------------------------------------------------------
# Per-route capability guard
# ---------------------------------------------------------------------------


def require_capability(capability: str) -> Callable[..., CurrentActor]:
    """Return a FastAPI dependency that enforces *capability* for the route.

    Usage::

        @router.patch("/catalogue", dependencies=[Depends(require_capability("catalogue:write"))])

    Or to receive the actor::

        @router.patch("/catalogue")
        async def patch(actor: Annotated[CurrentActor, Depends(require_capability("catalogue:write"))]):
            ...
    """

    async def _guard(
        actor: Annotated[CurrentActor, Depends(get_current_actor)],
    ) -> CurrentActor:
        allowed = PERSONA_CAPABILITIES.get(actor.persona, frozenset())
        if capability not in allowed:
            _LOG.warning(
                "authz_denied",
                extra={
                    "capability": capability,
                    "persona": actor.persona,
                    "actor_id": str(actor.user_id),
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "type": "https://pipelineshield.internal/errors/forbidden",
                    "title": "Forbidden",
                    "status": 403,
                    "detail": (
                        f"Your persona ({actor.persona!r}) does not have "
                        f"the {capability!r} capability."
                    ),
                    "errors": [],
                },
            )
        return actor

    return _guard
