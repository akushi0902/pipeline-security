"""Opaque cursor encoding for keyset pagination.

Cursors encode (occurred_at, id) as a base64url string with a CRC32 checksum
for tamper detection.  An invalid or tampered cursor raises CursorError which
the router converts to a 400 response.

Format (before base64 encoding):
    "<occurred_at_iso>|<id_uuid>|<crc32_hex>"

The CRC32 is computed over "<occurred_at_iso>|<id_uuid>" using binascii.crc32.
This is not a security primitive — it detects accidental corruption or
hand-crafted cursor values.  If stronger tamper-proofing is needed, replace
with HMAC-SHA256 using a rotating key.
"""
from __future__ import annotations

import binascii
import base64
import uuid
from datetime import datetime, timezone


class CursorError(ValueError):
    """Raised when a cursor string is malformed or fails integrity check."""


def encode_cursor(occurred_at: datetime, row_id: uuid.UUID) -> str:
    """Encode (occurred_at, row_id) into an opaque pagination cursor.

    Args:
        occurred_at: The timestamp of the row at the cursor boundary.
        row_id:      The UUID primary key of the row.

    Returns:
        A URL-safe base64 string safe to include in query parameters.
    """
    ts = occurred_at.astimezone(timezone.utc).isoformat()
    id_str = str(row_id)
    payload = f"{ts}|{id_str}"
    checksum = format(binascii.crc32(payload.encode()) & 0xFFFFFFFF, "08x")
    full = f"{payload}|{checksum}"
    return base64.urlsafe_b64encode(full.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    """Decode an opaque pagination cursor into (occurred_at, row_id).

    Args:
        cursor: The URL-safe base64 cursor string.

    Returns:
        Tuple of (occurred_at datetime with tzinfo=UTC, row_id UUID).

    Raises:
        CursorError: If the cursor is malformed or fails the integrity check.
    """
    # Restore padding stripped by encode_cursor.
    padding = (4 - len(cursor) % 4) % 4
    padded = cursor + "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(padded).decode()
    except Exception:
        raise CursorError("Cursor is not valid base64.")

    parts = decoded.rsplit("|", 1)
    if len(parts) != 2:
        raise CursorError("Cursor is missing checksum segment.")
    payload, received_checksum = parts

    expected = format(binascii.crc32(payload.encode()) & 0xFFFFFFFF, "08x")
    if received_checksum != expected:
        raise CursorError("Cursor checksum mismatch — cursor may have been tampered with.")

    inner_parts = payload.split("|", 1)
    if len(inner_parts) != 2:
        raise CursorError("Cursor payload has unexpected structure.")
    ts_str, id_str = inner_parts

    try:
        occurred_at = datetime.fromisoformat(ts_str).astimezone(timezone.utc)
    except ValueError:
        raise CursorError(f"Cursor timestamp is not a valid ISO 8601 datetime: {ts_str!r}")

    try:
        row_id = uuid.UUID(id_str)
    except ValueError:
        raise CursorError(f"Cursor row_id is not a valid UUID: {id_str!r}")

    return occurred_at, row_id
