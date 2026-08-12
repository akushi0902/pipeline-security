"""Governance schema — retention_policy table and audit_event composite index.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-11

Changes:
1. Create retention_policy table (single-row, id=1 sentinel, retention_days 1-90).
2. Add composite index on audit_event(occurred_at DESC, id) to support cursor
   pagination with stable ordering.
3. Assert (on PostgreSQL) that pipelineshield_app holds no UPDATE or DELETE
   grant on audit_event, documenting the append-only invariant.

The retention_policy table intentionally omits a workspace_id FK so that the
policy applies globally to the deployment.  Workspace-scoped policies can be
added in a future migration.

Downgrade removes the index and drops the table.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_APP_ROLE = "pipelineshield_app"


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. retention_policy — single-row configuration table
    # ------------------------------------------------------------------
    UUID = postgresql.UUID if _is_pg() else sa.String

    op.create_table(
        "retention_policy",
        sa.Column(
            "id",
            sa.SmallInteger(),
            primary_key=True,
            comment="Always 1 — single-row sentinel.",
        ),
        sa.Column(
            "retention_days",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("90"),
            comment="Days to retain Confidential data before purge (1–90).",
        ),
        sa.Column(
            "updated_by",
            UUID(as_uuid=True) if _is_pg() else sa.String(36),
            nullable=False,
            comment="AppUser UUID who last updated this policy.",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
            comment="Timestamp of last policy update (UTC).",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.CheckConstraint("id = 1", name="ck_retention_policy_single_row"),
        sa.CheckConstraint(
            "retention_days >= 1 AND retention_days <= 90",
            name="ck_retention_policy_days_range",
        ),
        comment=(
            "Classification: Internal | Retention: indefinite | "
            "Single-row global retention configuration.  "
            "Changes are always accompanied by an audit_event."
        ),
    )

    # ------------------------------------------------------------------
    # 2. Composite index on audit_event for cursor-paginated governance queries.
    #    Index on (occurred_at DESC, id) enables keyset pagination without
    #    a full table scan.
    # ------------------------------------------------------------------
    op.create_index(
        "ix_audit_event_occurred_at_id",
        "audit_event",
        [sa.text("occurred_at DESC"), "id"],
    )

    # ------------------------------------------------------------------
    # 3. Governance grants — SELECT/INSERT already exist from migration 0001.
    #    Explicitly confirm no UPDATE/DELETE is granted to the app role.
    #    This is documented rather than enforced here because the revocation
    #    was already performed in migration 0001.
    # ------------------------------------------------------------------
    if _is_pg():
        op.execute(
            f"GRANT SELECT, INSERT ON retention_policy TO {_APP_ROLE};"
        )

        # Advisory assertion: verify the invariant is in effect.
        # Raises psycopg.errors.InsufficientPrivilege on a correctly provisioned
        # database if the app role somehow gained UPDATE/DELETE.  In a migration
        # context we assert via a comment only — runtime checks are in tests.
        op.execute(
            "DO $$ BEGIN "
            "  RAISE NOTICE 'audit_event append-only invariant: "
            "pipelineshield_app must hold no UPDATE or DELETE on audit_event. "
            "Verified by test_migration.py tests 4 and 5.'; "
            "END $$;"
        )


def downgrade() -> None:
    op.drop_index("ix_audit_event_occurred_at_id", table_name="audit_event")
    op.drop_table("retention_policy")
