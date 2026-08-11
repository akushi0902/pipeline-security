"""RoleBinding model — persona assignments within a workspace.

Data classification: Internal
Retention: indefinite
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

# Valid persona values — kept in sync with the authorisation layer.
VALID_PERSONAS = (
    "app_developer",
    "devops_engineer",
    "devsecops_engineer",
    "appsec_lead",
    "engineering_manager",
)


class RoleBinding(Base):
    """Maps an AppUser to a persona within a workspace.

    A user may hold at most one persona per workspace (unique constraint on
    workspace_id + app_user_id).  The persona column is a discriminator used
    by AuthzGuard to determine the set of allowed capabilities.

    Deletion semantics: hard delete only.
    """

    __tablename__ = "role_binding"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "app_user_id",
            name="uq_role_binding_workspace_user",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — role binding identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Workspace this binding belongs to.",
    )
    app_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="User being granted the persona.",
    )
    persona: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "Persona label — one of: app_developer, devops_engineer, "
            "devsecops_engineer, appsec_lead, engineering_manager."
        ),
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Timestamp when the binding was created (UTC).",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship(  # type: ignore[name-defined]
        back_populates="role_bindings",
        lazy="raise",
    )
    app_user: Mapped["AppUser"] = relationship(  # type: ignore[name-defined]
        back_populates="role_bindings",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<RoleBinding id={self.id!r} "
            f"user={self.app_user_id!r} persona={self.persona!r}>"
        )
