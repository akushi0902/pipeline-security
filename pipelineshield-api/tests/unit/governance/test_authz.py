"""Unit tests for the authorization capability mapping.

Tests:
1. Governance personas (devsecops_engineer, appsec_lead) hold governance capabilities.
2. Non-governance personas (app_developer, engineering_manager, devops_engineer)
   do NOT hold governance capabilities.
3. Unknown persona holds no capabilities (deny-by-default).
4. All expected capabilities are present in the mapping.
5. No governance endpoint lacks a guard (verified via router inspection).
"""
from __future__ import annotations

import pytest

from pipelineshield.authz.capabilities import (
    Capability,
    PERSONA_CAPABILITIES,
    persona_has_capability,
)


# ---------------------------------------------------------------------------
# Governance capability tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("persona", ["devsecops_engineer", "appsec_lead"])
def test_governance_personas_have_read_capability(persona):
    assert persona_has_capability(persona, Capability.GOVERNANCE_READ)


@pytest.mark.parametrize("persona", ["devsecops_engineer", "appsec_lead"])
def test_governance_personas_have_write_capability(persona):
    assert persona_has_capability(persona, Capability.GOVERNANCE_WRITE)


@pytest.mark.parametrize(
    "persona",
    ["app_developer", "engineering_manager", "devops_engineer"],
)
def test_non_governance_personas_lack_read_capability(persona):
    assert not persona_has_capability(persona, Capability.GOVERNANCE_READ)


@pytest.mark.parametrize(
    "persona",
    ["app_developer", "engineering_manager", "devops_engineer"],
)
def test_non_governance_personas_lack_write_capability(persona):
    assert not persona_has_capability(persona, Capability.GOVERNANCE_WRITE)


def test_unknown_persona_has_no_capabilities():
    assert not persona_has_capability("unknown_persona", Capability.GOVERNANCE_READ)
    assert not persona_has_capability("unknown_persona", Capability.GOVERNANCE_WRITE)
    assert not persona_has_capability("unknown_persona", Capability.ANALYSIS_READ)


# ---------------------------------------------------------------------------
# Capability completeness
# ---------------------------------------------------------------------------


def test_all_capabilities_defined():
    defined = {c for caps in PERSONA_CAPABILITIES.values() for c in caps}
    for cap in Capability:
        assert cap in defined, f"Capability {cap} is not assigned to any persona"


def test_all_known_personas_in_mapping():
    from pipelineshield.persistence.models.role_binding import VALID_PERSONAS

    for persona in VALID_PERSONAS:
        assert persona in PERSONA_CAPABILITIES, (
            f"Persona {persona!r} from VALID_PERSONAS is not in PERSONA_CAPABILITIES"
        )


# ---------------------------------------------------------------------------
# Engineering manager is explicitly denied governance
# ---------------------------------------------------------------------------


def test_engineering_manager_denied_governance():
    for cap in [Capability.GOVERNANCE_READ, Capability.GOVERNANCE_WRITE]:
        assert not persona_has_capability("engineering_manager", cap), (
            f"engineering_manager must not hold {cap.value}"
        )


# ---------------------------------------------------------------------------
# Router guard coverage — verify no governance route is unguarded
# ---------------------------------------------------------------------------


def test_all_governance_routes_have_dependencies():
    """Assert every governance route declares at least one Depends."""
    pytest.importorskip("fastapi", reason="fastapi not installed")
    from pipelineshield.governance.router import router

    for route in router.routes:
        deps = getattr(route, "dependencies", [])
        assert len(deps) >= 1, (
            f"Governance route {route.path!r} has no declared dependency — "
            "it must require at least one AuthzGuard dependency."
        )
