"""Workflow manager: the decision layer between classification and tickets.

This is the component the specification calls the "workflow decision". It answers
one question - *does this turn need a ticket, and does it need a person?* - and
it answers it from the risk assessment in explicit code, never from model output.

The rules, in order:

1. **High or critical risk** creates a ticket owned by the security team, in the
   ``escalated`` state, flagged as requiring a human.
2. **Medium risk from a phishing or incident turn** opens a ticket for the
   security team, without a mandatory human step.
3. **IT support requests** are only *suggested*: the assistant tells the user a
   ticket can be raised, and the user decides. Specification scenario D asks for
   advice, not paperwork.
4. **Anything else** creates nothing.

If the same conversation already has a live ticket, a worse turn **escalates that
ticket** instead of opening a second one. Duplicate tickets for one incident are
how queues rot.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Literal

from sqlalchemy.orm import Session

from app.ai.turn_analysis import TurnAnalysis
from app.core.enums import Intent, RiskLevel, Role, Severity, TicketSource, TicketStatus
from app.db.models import Ticket, User
from app.security.audit import AuditAction, record_audit
from app.services.ticket_service import TicketService

logger = logging.getLogger(__name__)

WorkflowAction = Literal["none", "create", "escalate", "suggest"]

#: Intents that describe an event which has already happened.
INCIDENT_INTENTS = frozenset({Intent.PHISHING, Intent.SECURITY_INCIDENT})

#: Category recorded on the ticket, derived from the intent.
CATEGORY_BY_INTENT: dict[Intent, str] = {
    Intent.PHISHING: "phishing",
    Intent.SECURITY_INCIDENT: "incident",
    Intent.IT_SUPPORT: "it_support",
    Intent.POLICY_QUESTION: "policy",
    Intent.SECURITY_FAQ: "question",
    Intent.OUT_OF_SCOPE: "other",
}


@dataclasses.dataclass(frozen=True, slots=True)
class WorkflowDecision:
    """What should happen to the ticket system for this turn."""

    action: WorkflowAction
    reason: str
    title: str = ""
    description: str = ""
    category: str = "security"
    severity: Severity = Severity.LOW
    owner_role: Role = Role.SECURITY
    escalation_required: bool = False
    initial_status: TicketStatus = TicketStatus.OPEN
    suggested_action: str = ""

    @property
    def creates_ticket(self) -> bool:
        return self.action == "create"

    @property
    def escalates_ticket(self) -> bool:
        return self.action == "escalate"

    def audit_detail(self) -> dict[str, object]:
        return {
            "action": self.action,
            "reason": self.reason,
            "severity": self.severity.value,
            "owner_role": self.owner_role.value,
            "escalation_required": self.escalation_required,
        }


class WorkflowManager:
    """Decides and performs the ticket side of a turn."""

    def __init__(self, tickets: TicketService | None = None) -> None:
        self._tickets = tickets or TicketService()

    @property
    def tickets(self) -> TicketService:
        return self._tickets

    # -- decision ---------------------------------------------------------
    def decide(
        self,
        *,
        analysis: TurnAnalysis,
        question: str,
        existing_ticket: Ticket | None = None,
    ) -> WorkflowDecision:
        """Decide what this turn should do. Pure: it changes nothing."""
        risk = analysis.risk
        intent = analysis.intent
        title = self._title(question)
        category = CATEGORY_BY_INTENT.get(intent, "other")

        if analysis.blocked:
            return WorkflowDecision(
                action="none",
                reason="the request was refused, so there is no situation to track",
            )

        # 1. High and critical always involve a person.
        if risk.requires_escalation:
            if existing_ticket is not None:
                return WorkflowDecision(
                    action="escalate",
                    reason=(
                        f"risk is {risk.level.value}, and {existing_ticket.reference} already "
                        "tracks this conversation"
                    ),
                    title=title,
                    category=category,
                    severity=Severity.from_risk(risk.level),
                    owner_role=Role.SECURITY,
                    escalation_required=True,
                    initial_status=TicketStatus.ESCALATED,
                )
            return WorkflowDecision(
                action="create",
                reason=f"risk is {risk.level.value}, which requires a human response",
                title=title,
                description=self._description(analysis, question),
                category=category,
                severity=Severity.from_risk(risk.level),
                owner_role=Role.SECURITY,
                escalation_required=True,
                initial_status=TicketStatus.ESCALATED,
            )

        # 2. A confirmed medium-risk event is tracked, but not escalated.
        if risk.level is RiskLevel.MEDIUM and intent in INCIDENT_INTENTS:
            if existing_ticket is not None:
                # The existing ticket already covers it; nothing to do.
                return WorkflowDecision(
                    action="none",
                    reason=f"{existing_ticket.reference} already tracks this conversation",
                )
            return WorkflowDecision(
                action="create",
                reason="a medium-risk security event was reported",
                title=title,
                description=self._description(analysis, question),
                category=category,
                severity=Severity.MEDIUM,
                owner_role=Role.SECURITY,
                escalation_required=False,
                initial_status=TicketStatus.OPEN,
            )

        # 3. Service requests are offered, not imposed.
        if intent is Intent.IT_SUPPORT:
            if existing_ticket is not None:
                return WorkflowDecision(
                    action="none",
                    reason=f"{existing_ticket.reference} already tracks this conversation",
                )
            return WorkflowDecision(
                action="suggest",
                reason="a service request that a ticket would help track",
                title=title,
                category=category,
                severity=Severity.LOW,
                owner_role=Role.IT,
                suggested_action=(
                    "Raise an IT support ticket if the steps above do not resolve it."
                ),
            )

        return WorkflowDecision(
            action="none",
            reason=f"no ticket needed for a {risk.level.value}-risk {intent.value} turn",
        )

    # -- execution --------------------------------------------------------
    def apply(
        self,
        session: Session,
        *,
        decision: WorkflowDecision,
        user: User,
        analysis: TurnAnalysis,
        conversation_id: int | None,
        question: str,
        existing_ticket: Ticket | None = None,
    ) -> Ticket | None:
        """Carry out ``decision``. Returns the ticket that was created or escalated."""
        if decision.action == "create":
            ticket = self._tickets.create_ticket(
                session,
                title=decision.title,
                description=decision.description,
                severity=decision.severity,
                status=decision.initial_status,
                category=decision.category,
                owner_role=decision.owner_role,
                source=TicketSource.AI_AUTO,
                created_by=user,
                conversation_id=conversation_id,
                related_query=question,
                escalation_required=decision.escalation_required,
                automated=True,
                note=f"Created automatically by the assistant. {decision.reason}",
            )
            record_audit(
                session,
                action=AuditAction.TICKET_CREATED,
                actor=user,
                resource_type="ticket",
                resource_id=ticket.reference,
                detail={
                    "severity": ticket.severity.value,
                    "status": ticket.status.value,
                    "owner_role": ticket.owner_role.value,
                    "source": ticket.source.value,
                    "escalation_required": ticket.escalation_required,
                    "conversation_id": conversation_id,
                },
            )
            if ticket.escalation_required:
                # A ticket created straight into the escalated state is still an
                # escalation, and the timeline a reviewer reads has to say so.
                self._tickets.record_event(
                    session,
                    ticket,
                    event_type="escalated",
                    actor=user,
                    automated=True,
                    note=f"Escalated on creation. {decision.reason}",
                )
                record_audit(
                    session,
                    action=AuditAction.ESCALATION_TRIGGERED,
                    actor=user,
                    resource_type="ticket",
                    resource_id=ticket.reference,
                    detail={
                        "risk_level": analysis.risk.level.value,
                        "signals": [signal.label for signal in analysis.risk.signals],
                    },
                )
            return ticket

        if decision.action == "escalate" and existing_ticket is not None:
            ticket = self._tickets.escalate(
                session,
                ticket=existing_ticket,
                severity=decision.severity,
                reason=decision.reason,
                user=user,
                automated=True,
            )
            record_audit(
                session,
                action=AuditAction.ESCALATION_TRIGGERED,
                actor=user,
                resource_type="ticket",
                resource_id=ticket.reference,
                detail={
                    "risk_level": analysis.risk.level.value,
                    "severity": ticket.severity.value,
                    "signals": [signal.label for signal in analysis.risk.signals],
                },
            )
            return ticket

        if decision.action == "suggest":
            record_audit(
                session,
                action=AuditAction.TICKET_SUGGESTED,
                actor=user,
                resource_type="conversation",
                resource_id=conversation_id,
                detail={"suggested_owner": decision.owner_role.value},
            )
        return None

    # -- text -------------------------------------------------------------
    @staticmethod
    def _title(question: str) -> str:
        """A ticket title taken from the user's own words."""
        first_line = " ".join(question.strip().split())
        if len(first_line) <= 90:
            return first_line or "Security report"
        return first_line[:89].rstrip() + "…"

    def _description(self, analysis: TurnAnalysis, question: str) -> str:
        """Context for whoever picks the ticket up.

        Deliberately factual: what was asked, what the classifiers saw, and why
        the system raised it. It contains no document text and no credentials.
        """
        signals = ", ".join(signal.label for signal in analysis.risk.signals) or "none"
        lines = [
            "Raised automatically by the security assistant.",
            "",
            f"Reported by the user as: {question.strip()[:600]}",
            "",
            f"Assessed intent: {analysis.intent.value}",
            f"Assessed risk: {analysis.risk.level.value} (source: {analysis.risk.source})",
            f"Risk signals: {signals}",
            f"Assessment detail: {analysis.risk.reason}",
        ]
        if analysis.risk.escalated_from is not None:
            lines.append(
                f"This message alone scored {analysis.risk.escalated_from.value}; the "
                f"conversation was already at {analysis.risk.level.value}."
            )
        return "\n".join(lines)
