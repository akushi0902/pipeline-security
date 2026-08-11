"""Unit tests for governance cursor encoding/decoding.

Tests:
1. Round-trip: encode then decode returns original values.
2. Tampered checksum raises CursorError.
3. Truncated cursor raises CursorError.
4. Empty cursor raises CursorError.
5. Random bytes raise CursorError.
6. Timestamp precision is preserved (microseconds).
7. Multiple cursors are distinct.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

import pytest

from pipelineshield.governance.cursor import CursorError, decode_cursor, encode_cursor


@pytest.fixture
def sample_ts() -> datetime:
    return datetime(2025, 6, 15, 12, 30, 45, 123456, tzinfo=timezone.utc)


@pytest.fixture
def sample_id() -> uuid.UUID:
    return uuid.UUID("12345678-1234-5678-1234-567812345678")


def test_round_trip(sample_ts, sample_id):
    cursor = encode_cursor(sample_ts, sample_id)
    recovered_ts, recovered_id = decode_cursor(cursor)
    assert recovered_id == sample_id
    assert recovered_ts == sample_ts


def test_cursor_is_string(sample_ts, sample_id):
    cursor = encode_cursor(sample_ts, sample_id)
    assert isinstance(cursor, str)
    assert len(cursor) > 0


def test_cursor_url_safe(sample_ts, sample_id):
    cursor = encode_cursor(sample_ts, sample_id)
    # No padding characters and URL-safe alphabet only
    assert "+" not in cursor
    assert "/" not in cursor
    assert "=" not in cursor


def test_tampered_checksum_raises(sample_ts, sample_id):
    cursor = encode_cursor(sample_ts, sample_id)
    # Corrupt the last character of the base64 string.
    tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
    with pytest.raises(CursorError):
        decode_cursor(tampered)


def test_truncated_cursor_raises():
    with pytest.raises(CursorError):
        decode_cursor("abc")


def test_empty_cursor_raises():
    with pytest.raises(CursorError):
        decode_cursor("")


def test_random_bytes_raise():
    garbage = base64.urlsafe_b64encode(b"not-a-cursor-at-all").decode().rstrip("=")
    with pytest.raises(CursorError):
        decode_cursor(garbage)


def test_microseconds_preserved():
    ts = datetime(2026, 1, 1, 0, 0, 0, 999999, tzinfo=timezone.utc)
    uid = uuid.uuid4()
    cursor = encode_cursor(ts, uid)
    recovered_ts, recovered_id = decode_cursor(cursor)
    assert recovered_ts.microsecond == 999999
    assert recovered_id == uid


def test_distinct_cursors_for_different_inputs():
    ts1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
    ts2 = datetime(2025, 1, 2, tzinfo=timezone.utc)
    uid = uuid.uuid4()
    assert encode_cursor(ts1, uid) != encode_cursor(ts2, uid)


def test_boundary_min_timestamp():
    ts = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    uid = uuid.UUID("00000000-0000-0000-0000-000000000001")
    cursor = encode_cursor(ts, uid)
    recovered_ts, recovered_id = decode_cursor(cursor)
    assert recovered_id == uid
    assert recovered_ts == ts
