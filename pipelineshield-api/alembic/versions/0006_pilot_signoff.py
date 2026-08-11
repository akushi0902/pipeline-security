"""Pilot sign-off table and analysis duration column.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-11

Changes:
1. Create pilot_signoff table (append-only sign-off records, decision CHECK,
   accuracy rating CHECK 1-5, personas_covered text[], index on
   (workspace_id, recorded_at DESC)).
2. Add nullable duration_ms column to analysis to support latency percentile
   queries for the GA Gate status endpoint.
3. Grant SELECT, INSERT on pilot_signoff to pipelineshield_app.

Append-only semantics: corrections are new records, not updates.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_APP_ROLE = "pipelineshield_app"


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    UUID = postgresql.UUID if _is_pg() else sa.String

    # ------------------------------------------------------------------
    # 1. pilot_signoff — append-only pilot workspace sign-off records
    # ------------------------------------------------------------------
    op.create_table(
        "pilot_signoff",
        sa.Column(
            "id",
            UUID(as_uuid=True) if _is_pg() else sa.String(36),
            primary_key=True,
            comment="Primary key — sign-off record identifier.",
        ),
        sa.Column(
            "workspace_id",
            UUID(as_uuid=True) if _is_pg() else sa.String(36),
            sa.ForeignKey("workspace.id", ondelete="RESTRICT"),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "reviewer_user_id",
            UUID(as_uuid=True) if _is_pg() else sa.String(36),
            sa.ForeignKey("app_user.id", ondelete="RESTRICT"),
            nullable=False,
            comment="User who submitted this sign-off record.",
        ),
        sa.Column(
            "decision",
            sa.Text(),
            nullable=False,
            comment="Sign-off decision: approved, rejected, or pending.",
        ),
        sa.Column(
            "accuracy_actionability_rating",
            sa.SmallInteger(),
            nullable=True,
            comment=(
                "Pilot accuracy and actionability rating 1–5.  "
                "Required when decision is approved or rejected."
            ),
        ),
        sa.Column(
            "personas_covered",
            postgresql.ARRAY(sa.Text()) if _is_pg() else sa.JSON(),
            nullable=False,
            server_default="{}" if _is_pg() else "[]",
            comment="Personas represented by this reviewer.",
        ),
        sa.Column(
            "comments",
            sa.Text(),
            nullable=True,
            comment="Free-text reviewer comments.",
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
            comment="Timestamp when this record was committed (UTC).",
        ),
        sa.CheckConstraint(
            "decision IN ('approved', 'rejected', 'pending')",
            name="ck_pilot_signoff_decision",
        ),
        sa.CheckConstraint(
            "accuracy_actionability_rating IS NULL OR "
            "(accuracy_actionability_rating >= 1 AND accuracy_actionability_rating <= 5)",
            name="ck_pilot_signoff_accuracy_rating",
        ),
        comment=(
            "Classification: Confidential | Retention: 90 days | "
            "Append-only pilot workspace sign-off records.  "
            "Corrections are new records — no UPDATE path exists."
        ),
    )

    # Index to support scoped listing (workspace owner) and ordered pagination.
    op.create_index(
        "ix_pilot_signoff_workspace_recorded_at",
        "pilot_signoff",
        ["workspace_id", sa.text("recorded_at DESC")],
    )

    # ------------------------------------------------------------------
    # 2. Add duration_ms to analysis for latency percentile computation
    # ------------------------------------------------------------------
    op.add_column(
        "analysis",
        sa.Column(
            "duration_ms",
            sa.Integer(),
            nullable=True,
            comment=(
                "Wall-clock milliseconds from analysis start to completion. "
                "Null for analyses created before this migration."
            ),
        ),
    )

    # ------------------------------------------------------------------
    # 3. Grants
    # ------------------------------------------------------------------
    if _is_pg():
        op.execute(
            f"GRANT SELECT, INSERT ON pilot_signoff TO {_APP_ROLE};"
        )


def downgrade() -> None:
    op.drop_index("ix_pilot_signoff_workspace_recorded_at", table_name="pilot_signoff")
    op.drop_table("pilot_signoff")
    op.drop_column("analysis", "duration_ms")
