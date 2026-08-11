"""AppUser model — application user accounts.

Data classification: Internal
Retention: indefinite
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class AppUser(Base):
    """Application user account.

    Represents a real person authenticated via the enterprise IdP.  The
    sub_claim is the IdP subject claim (opaque string) and is the stable
    identifier used to correlate identity across sessions.

    Deletion semantics: hard delete only.
    """

    __tablename__ = "app_user"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — user identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Owning workspace — tenant scope.",
    )
    sub_claim: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="IdP subject claim (opaque); stable user identifier.",
    )
    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        comment="Email address from IdP claims.",
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Display name from IdP claims.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship(  # type: ignore[name-defined]
        back_populates="app_users",
        lazy="raise",
    )
    role_bindings: Mapped[list["RoleBinding"]] = relationship(  # type: ignore[name-defined]
        back_populates="app_user",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return f"<AppUser id={self.id!r} email={self.email!r}>"
