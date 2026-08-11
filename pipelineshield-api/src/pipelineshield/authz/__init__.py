"""Authorization module — capability-based RBAC for PipelineShield.

Provides the capability → persona mapping.  The FastAPI dependency (guard)
is imported on-demand to avoid pulling in fastapi at import time in contexts
that do not need the HTTP layer (e.g. unit tests).
"""
from .capabilities import Capability, PERSONA_CAPABILITIES, persona_has_capability

__all__ = [
    "Capability",
    "PERSONA_CAPABILITIES",
    "persona_has_capability",
]
