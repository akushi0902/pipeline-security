"""Unit tests for retention policy validation.

Tests:
1. Valid retention_days (1, 45, 90) pass Pydantic validation.
2. retention_days=0 fails validation.
3. retention_days=91 fails validation.
4. retention_days=100 fails validation.
5. Missing retention_days fails validation.
6. Non-integer retention_days fails validation.
7. Boundary values 1 and 90 are explicitly valid.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from pipelineshield.governance.models import RetentionPolicyUpdateRequest


@pytest.mark.parametrize("days", [1, 30, 45, 60, 89, 90])
def test_valid_retention_days(days):
    req = RetentionPolicyUpdateRequest(retention_days=days)
    assert req.retention_days == days


@pytest.mark.parametrize("days", [0, -1, 91, 100, 365])
def test_invalid_retention_days(days):
    with pytest.raises(ValidationError):
        RetentionPolicyUpdateRequest(retention_days=days)


def test_missing_retention_days():
    with pytest.raises(ValidationError):
        RetentionPolicyUpdateRequest()  # type: ignore[call-arg]


def test_non_integer_retention_days():
    with pytest.raises(ValidationError):
        RetentionPolicyUpdateRequest(retention_days="thirty")  # type: ignore[arg-type]


def test_boundary_min():
    req = RetentionPolicyUpdateRequest(retention_days=1)
    assert req.retention_days == 1


def test_boundary_max():
    req = RetentionPolicyUpdateRequest(retention_days=90)
    assert req.retention_days == 90


def test_max_plus_one_rejected():
    with pytest.raises(ValidationError) as exc_info:
        RetentionPolicyUpdateRequest(retention_days=91)
    errors = exc_info.value.errors()
    assert any(e["type"] in ("less_than_equal", "value_error") for e in errors)
