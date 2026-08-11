"""Scoring schema — analysis_category_score table and unscorable_reason column.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-11

Changes:
1. analysis: add unscorable_reason VARCHAR(255) NULLABLE.
2. Create analysis_category_score table — per-category score breakdown rows
   keyed by (analysis_id, category_id).

The analysis table already has score, grade, and catalogue_version_id from
migration 0001.  This migration adds the missing pieces required by
ScoringEngine.ScoreResult:
- unscorable_reason records the reason when all controls are Not Assessable.
- analysis_category_score stores the per-category breakdown produced by
  ScoringEngine.score() so it can be surfaced in reports and the dashboard.

Forward-only: downgrade drops the new table and column.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_APP_ROLE = "pipelineshield_app"


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. analysis: add unscorable_reason
    # ------------------------------------------------------------------
    with op.batch_alter_table("analysis", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "unscorable_reason",
                sa.String(255),
                nullable=True,
                comment=(
                    "Populated when all controls are Not Assessable and no "
                    "numeric score can be computed."
                ),
            )
        )

    # ------------------------------------------------------------------
    # 2. analysis_category_score
    # ------------------------------------------------------------------
    UUID = postgresql.UUID if _is_pg() else sa.String

    op.create_table(
        "analysis_category_score",
        sa.Column(
            "id",
            UUID(as_uuid=True) if _is_pg() else sa.String(36),
            primary_key=True,
            comment="Primary key.",
        ),
        sa.Column(
            "analysis_id",
            UUID(as_uuid=True) if _is_pg() else sa.String(36),
            sa.ForeignKey("analysis.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            comment="Parent analysis.",
        ),
        sa.Column(
            "category_id",
            sa.String(64),
            nullable=False,
            comment="Catalogue category identifier (e.g. secrets_hygiene).",
        ),
        sa.Column(
            "category_name",
            sa.String(255),
            nullable=False,
            comment="Human-readable category name at time of scoring.",
        ),
        sa.Column(
            "weight",
            sa.Integer(),
            nullable=False,
            comment="Category weight as configured in the active catalogue.",
        ),
        sa.Column(
            "earned",
            sa.Numeric(8, 4),
            nullable=False,
            comment="Decimal points earned for this category.",
        ),
        sa.Column(
            "possible",
            sa.Numeric(8, 4),
            nullable=False,
            comment="Maximum earnable points (denominator after NA exclusion).",
        ),
        sa.Column(
            "excluded_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
            comment="Number of controls excluded as Not Assessable.",
        ),
        sa.Column(
            "subscore",
            sa.Numeric(5, 2),
            nullable=True,
            comment="Category subscore percentage (null when all NA).",
        ),
        sa.UniqueConstraint(
            "analysis_id",
            "category_id",
            name="uq_analysis_category_score_analysis_category",
        ),
        comment=(
            "Per-category score breakdown produced by ScoringEngine. "
            "Classification: Confidential | Retention: 90 days."
        ),
    )

    op.create_index(
        "ix_analysis_category_score_analysis_id",
        "analysis_category_score",
        ["analysis_id"],
    )

    if _is_pg():
        op.execute(
            f"GRANT SELECT, INSERT ON analysis_category_score TO {_APP_ROLE};"
        )


def downgrade() -> None:
    op.drop_table("analysis_category_score")
    with op.batch_alter_table("analysis", schema=None) as batch_op:
        batch_op.drop_column("unscorable_reason")
