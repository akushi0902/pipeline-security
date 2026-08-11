"""Database engine and session factory.

Connection pool settings per architecture:
- pool_size: 10 per worker
- pool_pre_ping: True
- acquire timeout: 5 seconds
- statement timeout: 30 seconds

DATABASE_URL is injected at runtime from the environment.  No credentials
are hardcoded or stored in configuration files.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set.  "
            "Configure it before starting the service."
        )
    return url


def create_engine_from_env(
    *,
    pool_size: int = 10,
    max_overflow: int = 5,
    pool_pre_ping: bool = True,
    connect_args: dict | None = None,  # type: ignore[type-arg]
) -> "sqlalchemy.engine.Engine":  # type: ignore[name-defined]
    """Create a SQLAlchemy engine with the recommended pool settings."""
    if connect_args is None:
        # 5-second acquire timeout; 30-second statement timeout enforced
        # server-side.
        connect_args = {
            "connect_timeout": 5,
            "options": "-c statement_timeout=30000",
        }

    engine = create_engine(
        _get_database_url(),
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=pool_pre_ping,
        connect_args=connect_args,
    )
    return engine


def make_session_factory(
    engine: "sqlalchemy.engine.Engine",  # type: ignore[name-defined]
) -> sessionmaker[Session]:
    """Return a configured session factory bound to *engine*.

    Uses SQLAlchemy 2.0 style — no autocommit parameter (removed in 2.0;
    the session always uses autobegin mode).
    """
    return sessionmaker(engine, autoflush=False)


# ---------------------------------------------------------------------------
# FastAPI session dependency
# ---------------------------------------------------------------------------

_session_factory: sessionmaker[Session] | None = None


def init_session_factory(engine: "sqlalchemy.engine.Engine") -> None:  # type: ignore[name-defined]
    """Initialise the module-level session factory from the given engine.

    Call once at application startup, e.g. in the lifespan context manager.
    """
    global _session_factory
    _session_factory = make_session_factory(engine)


def get_session():  # type: ignore[return]
    """FastAPI dependency that yields a SQLAlchemy session per request.

    Commits on success, rolls back on exception.  Override this dependency
    in tests with a scoped test session.
    """
    if _session_factory is None:
        raise RuntimeError(
            "Session factory has not been initialised.  "
            "Call init_session_factory() at application startup."
        )
    session: Session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
