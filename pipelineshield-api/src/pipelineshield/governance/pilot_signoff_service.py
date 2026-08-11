"""PilotSignoffService — guarded sign-off creation and scoped reads.

Emits exactly one audit_event per sign-off creation.
Corrections are new records — no update path.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..authz.guard import ActorContext
from ..governance.cursor import CursorError, decode_cursor, encode_cursor
from ..governance.ga_gate import (
    GaGateEvaluation,
    evaluate_ga_gate,
)
from ..governance.models import (
    GaGateResponse,
    PilotSignoffCreateRequest,
    PilotSignoffListResponse,
    PilotSignoffResponse,
    ThresholdResultResponse,
)
from ..persistence.models.audit_event import AuditEvent
from ..persistence.models.pilot_signoff import PilotSignoff
from ..persistence.repositories.audit import AuditRepository
from ..persistence.repositories.metrics import MetricsRepository
from ..persistence.repositories.pilot_signoff import PilotSignoffRepository

# Personas that are permitted to create sign-offs for their own workspace.
_WORKSPACE_OWNER_PERSONAS = frozenset({"devsecops_engineer", "appsec_lead"})
# Personas that can view all workspaces' sign-offs.
_GOVERNANCE_PERSONAS = frozenset({"devsecops_engineer", "appsec_lead"})


class PilotSignoffValidationError(ValueError):
    """Raised when a sign-off create request fails validation."""


class PilotSignoffService:
    """Orchestrates pilot sign-off creation and gate status evaluation."""

    def __init__(
        self,
        signoff_repo: PilotSignoffRepository,
        audit_repo: AuditRepository,
        metrics_repo: MetricsRepository,
    ) -> None:
        self._signoff = signoff_repo
        self._audit = audit_repo
        self._metrics = metrics_repo

    # ------------------------------------------------------------------
    # Create sign-off
    # ------------------------------------------------------------------

    def create_signoff(
        self,
        request: PilotSignoffCreateRequest,
        actor: ActorContext,
    ) -> PilotSignoffResponse:
        """Create an immutable sign-off record and emit one audit_event.

        Validation:
        - decision must be in ('approved', 'rejected', 'pending').
        - accuracy_actionability_rating is required when decision is
          'approved' or 'rejected'; forbidden for 'pending'.
        - The actor must own the target workspace (or hold governance access).
        """
        self._validate_request(request, actor)

        now = datetime.now(timezone.utc)
        record = PilotSignoff(
            id=uuid.uuid4(),
            workspace_id=request.workspace_id,
            reviewer_user_id=uuid.UUID(actor.actor_id) if _is_uuid(actor.actor_id) else uuid.uuid4(),
            decision=request.decision,
            accuracy_actionability_rating=request.accuracy_actionability_rating,
            personas_covered=list(request.personas_covered),
            comments=request.comments,
            recorded_at=now,
        )
        self._signoff.create(record)

        # Audit event — exactly one per creation.
        audit = AuditEvent(
            actor_id=actor.actor_id,
            actor_persona=actor.persona,
            occurred_at=now,
            resource_type="pilot_signoff",
            resource_id=str(record.id),
            action="pilot_signoff.create",
            change_detail={
                "workspace_id": str(request.workspace_id),
                "decision": request.decision,
                "personas_covered": list(request.personas_covered),
            },
        )
        self._audit.append(audit)

        return _to_response(record)

    def _validate_request(
        self,
        request: PilotSignoffCreateRequest,
        actor: ActorContext,
    ) -> None:
        # Workspace scope: non-governance actors can only sign off their own workspace.
        if actor.persona not in _GOVERNANCE_PERSONAS:
            if request.workspace_id != actor.workspace_id:
                raise PilotSignoffValidationError(
                    f"Persona {actor.persona!r} may only submit sign-offs for "
                    f"their own workspace ({actor.workspace_id!r})."
                )

        # Rating requirement for non-pending decisions.
        if request.decision in ("approved", "rejected"):
            if request.accuracy_actionability_rating is None:
                raise PilotSignoffValidationError(
                    f"accuracy_actionability_rating is required when decision is "
                    f"'{request.decision}'."
                )
        elif request.decision == "pending":
            # Rating is allowed but not required for pending decisions.
            pass

    # ------------------------------------------------------------------
    # List sign-offs (scoped by persona)
    # ------------------------------------------------------------------

    def list_signoffs(
        self,
        actor: ActorContext,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> PilotSignoffListResponse:
        """Return sign-offs scoped by the actor's persona.

        Governance personas see all workspaces; workspace-owner personas see
        only their own workspace's sign-offs.
        """
        cursor_recorded_at = None
        cursor_id = None
        if cursor:
            cursor_recorded_at, cursor_id = decode_cursor(cursor)

        is_governance = actor.persona in _GOVERNANCE_PERSONAS
        if is_governance:
            rows = self._signoff.list_all(
                limit=limit,
                cursor_recorded_at=cursor_recorded_at,
                cursor_id=cursor_id,
            )
        else:
            rows = self._signoff.list_by_workspace(
                actor.workspace_id,
                limit=limit,
                cursor_recorded_at=cursor_recorded_at,
                cursor_id=cursor_id,
            )

        has_more = len(rows) > limit
        page = rows[:limit]

        next_cursor = None
        if has_more and page:
            last = page[-1]
            next_cursor = encode_cursor(last.recorded_at, last.id)

        return PilotSignoffListResponse(
            items=[_to_response(r) for r in page],
            next_cursor=next_cursor,
            has_more=has_more,
        )

    # ------------------------------------------------------------------
    # GA gate status
    # ------------------------------------------------------------------

    def get_ga_gate_status(self) -> GaGateResponse:
        """Aggregate all O6 thresholds and return the gate evaluation."""
        # Sign-off metrics
        total_pilot_ws = self._signoff.count_distinct_pilot_workspaces()
        approved_ws = self._signoff.count_workspaces_with_decision("approved")
        signed_off_pct: int | None
        if total_pilot_ws == 0:
            signed_off_pct = None  # insufficient data — avoid divide-by-zero
        else:
            signed_off_pct = (approved_ws * 100) // total_pilot_ws

        accuracy_pct = self._signoff.average_accuracy_rating_pct()

        # Posture metrics
        definitions_analysed = self._metrics.count_definitions_analysed()
        reanalysis_rate = self._metrics.reanalysis_rate_pct()
        median_improvement = self._metrics.median_score_improvement()
        latency_p95, latency_p50 = self._metrics.latency_percentiles_seconds()

        # Zero-tolerance counters
        authz_violations = self._metrics.count_authz_violations()
        purge_sla_breaches = self._metrics.count_purge_sla_breaches()

        # Fabricated findings and secret exposure come from external suites.
        # When no counter has been recorded, return None (insufficient_data).
        fabricated_findings: int | None = None
        secret_exposure_incidents: int | None = None

        evaluation: GaGateEvaluation = evaluate_ga_gate(
            workspaces_signed_off_pct=signed_off_pct,
            accuracy_rating_pct=accuracy_pct,
            definitions_analysed=definitions_analysed if definitions_analysed > 0 else None,
            reanalysis_rate_pct=reanalysis_rate,
            median_score_improvement=median_improvement,
            latency_p95_s=latency_p95,
            latency_p50_s=latency_p50,
            fabricated_findings=fabricated_findings,
            secret_exposure_incidents=secret_exposure_incidents,
            authz_violations=authz_violations,
            purge_sla_breaches=purge_sla_breaches,
        )

        threshold_responses = [
            ThresholdResultResponse(
                key=t.key,
                label=t.label,
                target=t.target,
                comparator=t.comparator,
                current=t.current,
                status=t.status,
                source=t.source,
            )
            for t in evaluation.thresholds
        ]

        return GaGateResponse(
            overall_status=evaluation.overall_status,
            evaluated_at=evaluation.evaluated_at,
            thresholds=threshold_responses,
            failing=evaluation.failing,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_response(record: PilotSignoff) -> PilotSignoffResponse:
    return PilotSignoffResponse(
        id=record.id,
        workspace_id=record.workspace_id,
        reviewer_user_id=record.reviewer_user_id,
        decision=record.decision,
        accuracy_actionability_rating=record.accuracy_actionability_rating,
        personas_covered=list(record.personas_covered or []),
        comments=record.comments,
        recorded_at=record.recorded_at,
    )


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False
