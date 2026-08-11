"""Capability definitions and persona → capability mapping.

Capabilities are fine-grained permissions.  Personas are assigned in the
role_binding table; AuthzGuard maps persona → capabilities at request time.

Governance capabilities are held only by devsecops_engineer and appsec_lead —
the two roles with a compliance/security remit in the E8 RBAC model.
"""
from __future__ import annotations

import enum


class Capability(str, enum.Enum):
    """Fine-grained capability tokens."""

    GOVERNANCE_READ = "governance:read"
    GOVERNANCE_WRITE = "governance:write"
    ANALYSIS_READ = "analysis:read"
    ANALYSIS_CREATE = "analysis:create"
    DEFINITION_READ = "definition:read"
    DEFINITION_CREATE = "definition:create"
    REMEDIATION_READ = "remediation:read"


# Mapping from persona label → set of capabilities.
# Personas not present in this map hold no capabilities (deny-by-default).
PERSONA_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "devsecops_engineer": frozenset(
        {
            Capability.GOVERNANCE_READ,
            Capability.GOVERNANCE_WRITE,
            Capability.ANALYSIS_READ,
            Capability.ANALYSIS_CREATE,
            Capability.DEFINITION_READ,
            Capability.DEFINITION_CREATE,
            Capability.REMEDIATION_READ,
        }
    ),
    "appsec_lead": frozenset(
        {
            Capability.GOVERNANCE_READ,
            Capability.GOVERNANCE_WRITE,
            Capability.ANALYSIS_READ,
            Capability.ANALYSIS_CREATE,
            Capability.DEFINITION_READ,
            Capability.REMEDIATION_READ,
        }
    ),
    "devops_engineer": frozenset(
        {
            Capability.ANALYSIS_READ,
            Capability.ANALYSIS_CREATE,
            Capability.DEFINITION_READ,
            Capability.DEFINITION_CREATE,
            Capability.REMEDIATION_READ,
        }
    ),
    "app_developer": frozenset(
        {
            Capability.ANALYSIS_READ,
            Capability.DEFINITION_READ,
            Capability.REMEDIATION_READ,
        }
    ),
    "engineering_manager": frozenset(
        {
            Capability.ANALYSIS_READ,
            Capability.REMEDIATION_READ,
        }
    ),
}


def persona_has_capability(persona: str, capability: Capability) -> bool:
    """Return True iff the given persona holds the requested capability."""
    return capability in PERSONA_CAPABILITIES.get(persona, frozenset())
