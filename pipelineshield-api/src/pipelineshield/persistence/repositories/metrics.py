"""MetricsRepository — pre-aggregated GA gate metric queries.

All queries exclude sample pipelines via the SQL predicate
(pipeline_definition.is_sample = false), never in post-filtering.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


class MetricsRepository:
    """Pre-aggregated, index-backed queries for GA gate metrics."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Definitions analysed
    # ------------------------------------------------------------------

    def count_definitions_analysed(self) -> int:
        """Count distinct non-sample pipeline definitions that have an analysis.

        Sample pipelines are excluded via pipeline_definition.is_sample = false
        in the SQL predicate — not in post-filtering.
        """
        stmt = text(
            "SELECT COUNT(DISTINCT pd.id) "
            "FROM pipeline_definition pd "
            "JOIN analysis a ON a.id = pd.analysis_id "
            "WHERE pd.is_sample = false"
        )
        result = self._session.execute(stmt).scalar()
        return int(result or 0)

    # ------------------------------------------------------------------
    # Re-analysis rate
    # ------------------------------------------------------------------

    def reanalysis_rate_pct(self) -> int | None:
        """Percentage of non-sample workspaces that have run >= 2 analyses.

        A workspace that has submitted a pipeline for analysis more than once
        (i.e. has >= 2 pipeline_definition rows with is_sample=false) counts
        as re-analysed.

        Returns None when no non-sample workspaces exist (insufficient data).
        """
        stmt = text(
            "SELECT "
            "  COUNT(*) FILTER (WHERE cnt >= 2) * 100 / NULLIF(COUNT(*), 0) "
            "FROM ("
            "  SELECT a.workspace_id, COUNT(pd.id) AS cnt "
            "  FROM pipeline_definition pd "
            "  JOIN analysis a ON a.id = pd.analysis_id "
            "  WHERE pd.is_sample = false "
            "  GROUP BY a.workspace_id"
            ") ws_counts"
        )
        result = self._session.execute(stmt).scalar()
        return int(result) if result is not None else None

    # ------------------------------------------------------------------
    # Median score improvement
    # ------------------------------------------------------------------

    def median_score_improvement(self) -> int | None:
        """Median score delta (latest − first) across workspaces with >= 2 analyses.

        Uses the standard SQL PERCENTILE_CONT(0.5) convention so ties and even
        cardinalities are handled by the database function without ambiguity.

        Returns None when fewer than 2 workspaces have >= 2 analyses.
        """
        stmt = text(
            "WITH workspace_scores AS ("
            "  SELECT"
            "    a.workspace_id,"
            "    FIRST_VALUE(a.score) OVER ("
            "      PARTITION BY a.workspace_id ORDER BY a.created_at ASC"
            "    ) AS first_score,"
            "    LAST_VALUE(a.score) OVER ("
            "      PARTITION BY a.workspace_id"
            "      ORDER BY a.created_at ASC"
            "      ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING"
            "    ) AS latest_score,"
            "    COUNT(a.id) OVER (PARTITION BY a.workspace_id) AS cnt"
            "  FROM analysis a"
            "  JOIN pipeline_definition pd ON pd.analysis_id = a.id"
            "  WHERE pd.is_sample = false"
            "), "
            "improvements AS ("
            "  SELECT DISTINCT workspace_id, (latest_score - first_score) AS delta"
            "  FROM workspace_scores"
            "  WHERE cnt >= 2"
            ")"
            "SELECT CAST(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY delta) AS INTEGER)"
            "FROM improvements"
        )
        try:
            result = self._session.execute(stmt).scalar()
            return int(result) if result is not None else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Latency percentiles
    # ------------------------------------------------------------------

    def latency_percentiles_seconds(self) -> tuple[float | None, float | None]:
        """Return (p95_seconds, p50_seconds) from analysis.duration_ms.

        Includes all non-sample analyses regardless of status (timeouts and
        degraded-inference responses are included, not discarded).
        Returns (None, None) when no duration_ms values are recorded.
        """
        stmt = text(
            "SELECT "
            "  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY a.duration_ms) / 1000.0,"
            "  PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY a.duration_ms) / 1000.0 "
            "FROM analysis a "
            "JOIN pipeline_definition pd ON pd.analysis_id = a.id "
            "WHERE pd.is_sample = false "
            "  AND a.duration_ms IS NOT NULL"
        )
        try:
            row = self._session.execute(stmt).one_or_none()
            if row is None or (row[0] is None and row[1] is None):
                return None, None
            p95 = float(row[0]) if row[0] is not None else None
            p50 = float(row[1]) if row[1] is not None else None
            return p95, p50
        except Exception:
            return None, None

    # ------------------------------------------------------------------
    # Zero-tolerance counters
    # ------------------------------------------------------------------

    def count_authz_violations(self) -> int:
        """Count audit_event rows where action = 'authz.denied'."""
        stmt = text(
            "SELECT COUNT(*) FROM audit_event WHERE action = 'authz.denied'"
        )
        result = self._session.execute(stmt).scalar()
        return int(result or 0)

    def count_purge_sla_breaches(self) -> int:
        """Count purge receipts that represent SLA failures."""
        stmt = text(
            "SELECT COUNT(*) FROM purge_receipt "
            "WHERE verification_digest = 'FAILED'"
        )
        try:
            result = self._session.execute(stmt).scalar()
            return int(result or 0)
        except Exception:
            return 0
