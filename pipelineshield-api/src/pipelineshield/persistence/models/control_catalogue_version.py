"""ControlCatalogueVersion model — versioned security control catalogue.

Data classification: Internal
Retention: indefinite
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class ControlCatalogueVersion(Base):
    """Versioned snapshot of the security control catalogue.

    Every analysis records the catalogue_version it was scored against.
    Versioning ensures that historical results remain valid as the
    catalogue evolves — re-running the catalogue on old data is always
    possible by joining on the version stamp.

    Deletion semantics: hard delete only (Internal classification).
    """

    __tablename__ = "control_catalogue_version"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — catalogue version identifier.",
    )
    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        unique=True,
        comment="Monotonically increasing version counter.",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        comment="Human-readable change notes for this catalogue version.",
    )
    controls: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        comment="Full catalogue snapshot as JSONB.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    analyses: Mapped[list["Analysis"]] = relationship(  # type: ignore[name-defined]
        back_populates="catalogue_version",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<ControlCatalogueVersion id={self.id!r} "
            f"version_number={self.version_number!r}>"
        )
