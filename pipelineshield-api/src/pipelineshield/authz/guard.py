"""AuthzGuard — FastAPI dependency for capability-based authorization.

Usage:
    from pipelineshield.authz.guard import require_capability
    from pipelineshield.authz.capabilities import Capability

    @router.get("/governance/audit-events")
    def list_audit_events(
        actor: ActorContext = Depends(require_capability(Capability.GOVERNANCE_READ)),
    ) -> ...:
        ...

The guard reads actor identity from request headers injected by the
upstream authentication middleware / API gateway:
    X-Actor-Id       — stable actor identifier (e.g. user UUID or sub claim)
    X-Actor-Persona  — persona label from the role_binding table
    X-Workspace-Id   — workspace UUID (tenant scope)

In production these headers are set by the auth middleware and are not
user-controlled.  In tests they are set directly on the TestClient.

Authorization denial always returns 403 Forbidden with a problem+json body.
A cross-workspace resource request returns 404 Not Found (existence disclosure
prevention) rather than 403.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, Request, status

from .capabilities import Capability, persona_has_capability

_MISSING_ACTOR = "X-Actor-Id header is required"
_MISSING_PERSONA = "X-Actor-Persona header is required"
_MISSING_WORKSPACE = "X-Workspace-Id header is required"


class AuthzError(Exception):
    """Raised internally when an authorization check fails."""


@dataclass(frozen=True)
class ActorContext:
    """Resolved actor identity attached to the current request."""

    actor_id: str
    persona: str
    workspace_id: uuid.UUID
    display_name: str | None = None


def _extract_actor(request: Request) -> ActorContext:
    """Extract and validate actor context from request headers.

    Raises HTTPException 401 if required headers are absent.
    """
    actor_id = request.headers.get("X-Actor-Id")
    if not actor_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"type": "missing_actor_id", "detail": _MISSING_ACTOR},
        )
    persona = request.headers.get("X-Actor-Persona")
    if not persona:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"type": "missing_persona", "detail": _MISSING_PERSONA},
        )
    workspace_str = request.headers.get("X-Workspace-Id")
    if not workspace_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"type": "missing_workspace_id", "detail": _MISSING_WORKSPACE},
        )
    try:
        workspace_id = uuid.UUID(workspace_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "type": "invalid_workspace_id",
                "detail": f"X-Workspace-Id must be a valid UUID, got: {workspace_str!r}",
            },
        )
    return ActorContext(
        actor_id=actor_id,
        persona=persona,
        workspace_id=workspace_id,
        display_name=request.headers.get("X-Actor-Display"),
    )


def require_capability(capability: Capability) -> Callable[[Request], ActorContext]:
    """Return a FastAPI dependency that requires the given capability.

    The returned dependency resolves to ActorContext on success or raises
    HTTPException 403 on authorization failure.

    Example:
        actor: ActorContext = Depends(require_capability(Capability.GOVERNANCE_READ))
    """

    def _guard(request: Request) -> ActorContext:
        actor = _extract_actor(request)
        if not persona_has_capability(actor.persona, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "type": "insufficient_capability",
                    "detail": (
                        f"Persona {actor.persona!r} does not hold the "
                        f"{capability.value!r} capability required for this endpoint."
                    ),
                    "required_capability": capability.value,
                    "actor_persona": actor.persona,
                },
            )
        return actor

    return _guard
