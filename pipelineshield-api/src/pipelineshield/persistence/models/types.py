"""Dialect-aware SQLAlchemy column types.

DialectJSON renders as JSONB on PostgreSQL (index-able, GIN-friendly) and as
the standard JSON type on SQLite — both behave identically for read-back
equality assertions and checksum comparison.

DialectTextArray renders as ARRAY(Text) on PostgreSQL and as JSON (storing a
JSON array) on SQLite for cross-dialect test compatibility.
"""
from __future__ import annotations

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator


class DialectJSON(TypeDecorator):
    """JSONB on PostgreSQL, JSON everywhere else.

    Using TypeDecorator + load_dialect_impl is the correct SQLAlchemy 2.0
    pattern for dialect-specific type selection without conditional imports
    at column definition time.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):  # type: ignore[override]
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class DialectTextArray(TypeDecorator):
    """ARRAY(Text) on PostgreSQL, JSON (list) everywhere else.

    Stores text arrays as native Postgres arrays on PostgreSQL and as
    JSON arrays on other databases (e.g. SQLite for unit tests).
    Python-side value is always a list[str].
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):  # type: ignore[override]
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(Text()))
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):  # type: ignore[override]
        if value is None:
            return []
        return list(value)

    def process_result_value(self, value, dialect):  # type: ignore[override]
        if value is None:
            return []
        return list(value)
