"""Dashboard aggregation.

Everything here is a **count or an aggregate**. The dashboard answers "how much,
how often, how severe" - it never returns conversation text, answer content,
document bodies or credentials, because a statistics screen is exactly the kind
of surface that quietly becomes a data-export tool.

Design notes:

* Aggregation happens in SQL. Classification is denormalised onto the message row
  precisely so this is a ``GROUP BY`` rather than a full table scan in Python.
* Each query is bounded by a time window, so the cost stays flat as the audit log
  grows.
* The audit-log search returns metadata only; the ``detail`` column already
  stores counts and identifiers rather than content.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.enums import AuditOutcome, Intent, RiskLevel, Role, Severity, TicketStatus
from app.db.models import (
    AuditLog,
    Conversation,
    Message,
    Ticket,
    TicketEvent,
    User,
    UserSession,
)

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_DAYS = 14
MAX_WINDOW_DAYS = 180
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

#: Audit actions that mean "somebody was refused something". A rising count is
#: the signal a security team most wants to see on a dashboard.
DENIED_ACTIONS = (
    "authz.denied",
    "auth.login.failure",
    "auth.login.denied",
    "auth.login.throttled",
    "chat.query.blocked",
    "chat.conversation.denied",
    "ticket.access.denied",
    "ticket.status.denied",
    "knowledge.document.denied",
    "rag.retrieval.denied",
)


def _since(days: int) -> dt.datetime:
    return dt.datetime.now(dt.UTC) - dt.timedelta(days=max(1, min(days, MAX_WINDOW_DAYS)))


def _grouped_counts(session: Session, statement: Select[Any]) -> dict[str, int]:
    """Run a ``SELECT key, COUNT(*) GROUP BY key`` and return a plain dict."""
    return {str(key): int(count or 0) for key, count in session.execute(statement).all()}


def _fill(domain: list[str], counts: dict[str, int]) -> dict[str, int]:
    """Fill in zeroes so the UI shows an empty bar rather than a missing one."""
    return {key: counts.get(key, 0) for key in domain}


@dataclasses.dataclass(frozen=True, slots=True)
class AuditQuery:
    """Filters for the audit-log search."""

    action: str | None = None
    actor_role: str | None = None
    outcome: str | None = None
    since_days: int = DEFAULT_WINDOW_DAYS
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0


class DashboardService:
    """Read-only aggregates over conversations, tickets and the audit trail."""

    # -- headline ---------------------------------------------------------
    def summary(self, session: Session, *, days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
        """Headline counters. Every value is an integer or a timestamp."""
        window_start = _since(days)

        conversation_total = int(session.scalar(select(func.count(Conversation.id))) or 0)
        question_total = int(
            session.scalar(select(func.count(Message.id)).where(Message.role == "user")) or 0
        )
        window_questions = int(
            session.scalar(
                select(func.count(Message.id)).where(
                    Message.role == "user", Message.created_at >= window_start
                )
            )
            or 0
        )

        escalated_total = int(
            session.scalar(select(func.count(Message.id)).where(Message.escalated.is_(True))) or 0
        )
        window_escalations = int(
            session.scalar(
                select(func.count(Message.id)).where(
                    Message.escalated.is_(True), Message.created_at >= window_start
                )
            )
            or 0
        )

        tickets_open = int(
            session.scalar(
                select(func.count(Ticket.id)).where(
                    Ticket.status.notin_([TicketStatus.RESOLVED, TicketStatus.CLOSED])
                )
            )
            or 0
        )
        tickets_requiring_human = int(
            session.scalar(
                select(func.count(Ticket.id)).where(
                    Ticket.escalation_required.is_(True),
                    Ticket.status.notin_([TicketStatus.RESOLVED, TicketStatus.CLOSED]),
                )
            )
            or 0
        )
        tickets_unacknowledged = int(
            session.scalar(
                select(func.count(Ticket.id)).where(
                    Ticket.escalation_required.is_(True),
                    Ticket.status == TicketStatus.OPEN,
                )
            )
            or 0
        )

        denied_window = int(
            session.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action.in_(DENIED_ACTIONS), AuditLog.created_at >= window_start
                )
            )
            or 0
        )
        blocked_queries = int(
            session.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "chat.query.blocked", AuditLog.created_at >= window_start
                )
            )
            or 0
        )
        access_denials = int(
            session.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action.in_(
                        [
                            "authz.denied",
                            "ticket.access.denied",
                            "knowledge.document.denied",
                            "chat.conversation.denied",
                        ]
                    ),
                    AuditLog.created_at >= window_start,
                )
            )
            or 0
        )

        active_users = int(
            session.scalar(
                select(func.count(func.distinct(AuditLog.actor_user_id))).where(
                    AuditLog.created_at >= window_start, AuditLog.actor_user_id.is_not(None)
                )
            )
            or 0
        )
        active_sessions = int(
            session.scalar(
                select(func.count(UserSession.id)).where(UserSession.revoked_at.is_(None))
            )
            or 0
        )
        total_users = int(session.scalar(select(func.count(User.id))) or 0)
        locked_or_disabled = int(
            session.scalar(select(func.count(User.id)).where(User.is_active.is_(False))) or 0
        )

        return {
            "window_days": days,
            "window_start": window_start.isoformat(),
            "users": {
                "total": total_users,
                "disabled": locked_or_disabled,
                "active_in_window": active_users,
                "active_sessions": active_sessions,
            },
            "conversations": {"total": conversation_total},
            "questions": {"total": question_total, "in_window": window_questions},
            "escalations": {"total": escalated_total, "in_window": window_escalations},
            "tickets": {
                "open": tickets_open,
                "requiring_human": tickets_requiring_human,
                "unacknowledged": tickets_unacknowledged,
            },
            "security_signals": {
                "denied_total": denied_window,
                "access_denials": access_denials,
                "blocked_prompt_injections": blocked_queries,
            },
        }

    # -- timeseries -------------------------------------------------------
    def timeseries(self, session: Session, *, days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
        """Daily counts, with every day present so the UI can plot a flat line."""
        days = max(1, min(days, MAX_WINDOW_DAYS))
        window_start = _since(days)
        day = func.date(Message.created_at)

        questions = _grouped_counts(
            session,
            select(day, func.count(Message.id))
            .where(Message.role == "user", Message.created_at >= window_start)
            .group_by(day),
        )
        escalations = _grouped_counts(
            session,
            select(day, func.count(Message.id))
            .where(Message.escalated.is_(True), Message.created_at >= window_start)
            .group_by(day),
        )

        audit_day = func.date(AuditLog.created_at)
        denials = _grouped_counts(
            session,
            select(audit_day, func.count(AuditLog.id))
            .where(AuditLog.action.in_(DENIED_ACTIONS), AuditLog.created_at >= window_start)
            .group_by(audit_day),
        )
        logins = _grouped_counts(
            session,
            select(audit_day, func.count(AuditLog.id))
            .where(AuditLog.action == "auth.login.success", AuditLog.created_at >= window_start)
            .group_by(audit_day),
        )
        tickets = _grouped_counts(
            session,
            select(func.date(Ticket.created_at), func.count(Ticket.id))
            .where(Ticket.created_at >= window_start)
            .group_by(func.date(Ticket.created_at)),
        )

        today = dt.datetime.now(dt.UTC).date()
        series = []
        for offset in range(days - 1, -1, -1):
            key = (today - dt.timedelta(days=offset)).isoformat()
            series.append(
                {
                    "date": key,
                    "questions": questions.get(key, 0),
                    "escalations": escalations.get(key, 0),
                    "tickets": tickets.get(key, 0),
                    "denials": denials.get(key, 0),
                    "logins": logins.get(key, 0),
                }
            )

        return {"window_days": days, "series": series}

    # -- distributions ----------------------------------------------------
    def distributions(self, session: Session, *, days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
        """How the traffic breaks down by classification and ticket state."""
        window_start = _since(days)
        answered = Message.role == "assistant"

        risk_counts = _grouped_counts(
            session,
            select(Message.risk_level, func.count(Message.id))
            .where(answered, Message.created_at >= window_start, Message.risk_level.is_not(None))
            .group_by(Message.risk_level),
        )
        intent_counts = _grouped_counts(
            session,
            select(Message.intent, func.count(Message.id))
            .where(answered, Message.created_at >= window_start, Message.intent.is_not(None))
            .group_by(Message.intent),
        )
        ticket_status = _grouped_counts(
            session,
            select(Ticket.status, func.count(Ticket.id)).group_by(Ticket.status),
        )
        ticket_severity = _grouped_counts(
            session,
            select(Ticket.severity, func.count(Ticket.id)).group_by(Ticket.severity),
        )
        ticket_owner = _grouped_counts(
            session,
            select(Ticket.owner_role, func.count(Ticket.id)).group_by(Ticket.owner_role),
        )
        ticket_source = _grouped_counts(
            session,
            select(Ticket.source, func.count(Ticket.id)).group_by(Ticket.source),
        )
        actions = _grouped_counts(
            session,
            select(AuditLog.action, func.count(AuditLog.id))
            .where(AuditLog.created_at >= window_start)
            .group_by(AuditLog.action)
            .order_by(func.count(AuditLog.id).desc())
            .limit(12),
        )

        return {
            "window_days": days,
            "risk_levels": _fill([level.value for level in RiskLevel], risk_counts),
            "intents": _fill([intent.value for intent in Intent], intent_counts),
            "ticket_status": _fill([status.value for status in TicketStatus], ticket_status),
            "ticket_severity": _fill([severity.value for severity in Severity], ticket_severity),
            "ticket_owner_role": _fill([role.value for role in Role], ticket_owner),
            "ticket_source": dict(sorted(ticket_source.items(), key=lambda item: -item[1])),
            "top_actions": [
                {"action": action, "count": count} for action, count in actions.items()
            ],
        }

    # -- response performance --------------------------------------------
    def response_times(
        self, session: Session, *, days: int = DEFAULT_WINDOW_DAYS
    ) -> dict[str, Any]:
        """How long escalated tickets waited for a human to pick them up."""
        window_start = _since(days)
        created = (
            select(
                Ticket.id.label("ticket_id"),
                Ticket.created_at.label("created_at"),
            )
            .where(Ticket.created_at >= window_start, Ticket.escalation_required.is_(True))
            .subquery()
        )
        acknowledged = (
            select(
                TicketEvent.ticket_id.label("ticket_id"),
                func.min(TicketEvent.created_at).label("acknowledged_at"),
            )
            .where(TicketEvent.automated.is_(False))
            .group_by(TicketEvent.ticket_id)
            .subquery()
        )
        rows = session.execute(
            select(created.c.created_at, acknowledged.c.acknowledged_at).join(
                acknowledged, acknowledged.c.ticket_id == created.c.ticket_id, isouter=True
            )
        ).all()

        waited: list[float] = []
        unacknowledged = 0
        for created_at, acknowledged_at in rows:
            if acknowledged_at is None:
                unacknowledged += 1
                continue
            delta = acknowledged_at - created_at
            waited.append(max(0.0, delta.total_seconds()))

        waited.sort()
        if waited:
            middle = waited[len(waited) // 2]
            metrics: dict[str, Any] = {
                "median_seconds": round(middle, 1),
                "slowest_seconds": round(waited[-1], 1),
                "fastest_seconds": round(waited[0], 1),
            }
        else:
            metrics = {"median_seconds": None, "slowest_seconds": None, "fastest_seconds": None}

        return {
            "window_days": days,
            "escalated_tickets": len(rows),
            "acknowledged": len(waited),
            "still_unacknowledged": unacknowledged,
            **metrics,
        }

    # -- audit search -----------------------------------------------------
    def audit_log(self, session: Session, query: AuditQuery) -> dict[str, Any]:
        """Search the audit trail. Metadata only - never content."""
        statement = select(AuditLog)
        counter = select(func.count(AuditLog.id))

        conditions = [AuditLog.created_at >= _since(query.since_days)]
        if query.action:
            conditions.append(AuditLog.action == query.action)
        if query.actor_role:
            conditions.append(AuditLog.actor_role == query.actor_role)
        if query.outcome:
            conditions.append(AuditLog.outcome == query.outcome)

        statement = statement.where(*conditions)
        counter = counter.where(*conditions)

        total = int(session.scalar(counter) or 0)
        rows = session.scalars(
            statement.order_by(AuditLog.id.desc())
            .limit(max(1, min(query.limit, MAX_PAGE_SIZE)))
            .offset(max(0, query.offset))
        ).all()

        return {
            "total": total,
            "returned": len(rows),
            "offset": query.offset,
            "entries": [self._entry(row) for row in rows],
        }

    @staticmethod
    def _entry(row: AuditLog) -> dict[str, Any]:
        """One audit record, projected onto the fields a reviewer needs.

        The raw ``detail`` blob is deliberately *not* returned wholesale: it is
        summarised into a short list of key names, which tells a reviewer what
        context exists without turning the endpoint into a bulk export.
        """
        detail_keys = sorted(row.detail.keys()) if isinstance(row.detail, dict) else []
        return {
            "id": row.id,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "action": row.action,
            "outcome": row.outcome.value,
            "actor_role": row.actor_role,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "request_id": row.request_id,
            "ip_address": row.ip_address,
            "detail_keys": detail_keys,
        }

    def audit_actions(self, session: Session) -> list[str]:
        """The distinct actions present, so the UI can offer a filter list."""
        return sorted(
            str(action) for action in session.scalars(select(AuditLog.action).distinct()).all()
        )

    # -- knowledge access ------------------------------------------------
    def document_access(
        self, session: Session, *, days: int = DEFAULT_WINDOW_DAYS
    ) -> dict[str, Any]:
        """Which documents were read, and which attempts were refused."""
        window_start = _since(days)
        refused = _grouped_counts(
            session,
            select(AuditLog.resource_id, func.count(AuditLog.id))
            .where(
                AuditLog.action == "knowledge.document.denied",
                AuditLog.created_at >= window_start,
            )
            .group_by(AuditLog.resource_id)
            .order_by(func.count(AuditLog.id).desc())
            .limit(10),
        )
        viewed = _grouped_counts(
            session,
            select(AuditLog.resource_id, func.count(AuditLog.id))
            .where(
                AuditLog.action == "knowledge.document.viewed",
                AuditLog.created_at >= window_start,
            )
            .group_by(AuditLog.resource_id)
            .order_by(func.count(AuditLog.id).desc())
            .limit(10),
        )
        by_role = _grouped_counts(
            session,
            select(AuditLog.actor_role, func.count(AuditLog.id))
            .where(AuditLog.action.in_(DENIED_ACTIONS), AuditLog.created_at >= window_start)
            .group_by(AuditLog.actor_role),
        )

        return {
            "window_days": days,
            "most_viewed_documents": [
                {"document_id": key, "count": value} for key, value in viewed.items()
            ],
            "most_refused_documents": [
                {"document_id": key, "count": value} for key, value in refused.items()
            ],
            "denials_by_role": _fill([role.value for role in Role], by_role),
        }

    def overview(self, session: Session, *, days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
        """Everything the dashboard needs in one round trip."""
        return {
            "summary": self.summary(session, days=days),
            "timeseries": self.timeseries(session, days=days),
            "distributions": self.distributions(session, days=days),
            "response_times": self.response_times(session, days=days),
            "document_access": self.document_access(session, days=days),
            "outcomes": self.outcomes(session, days=days),
        }

    def outcomes(self, session: Session, *, days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
        """Audit outcomes, so a spike in denials is visible at a glance."""
        window_start = _since(days)
        counts = _grouped_counts(
            session,
            select(AuditLog.outcome, func.count(AuditLog.id))
            .where(AuditLog.created_at >= window_start)
            .group_by(AuditLog.outcome),
        )
        return {"window_days": days, "by_outcome": _fill([o.value for o in AuditOutcome], counts)}
