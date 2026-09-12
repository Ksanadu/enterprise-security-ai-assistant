"""Append-only audit trail.

Every security-relevant decision - successful or denied - is recorded here. The
audit writer is intentionally failure-tolerant: a broken audit sink must not turn
a valid request into a 500, but it must always be logged loudly.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.enums import AuditOutcome
from app.core.logging import request_id_var
from app.db.models import AuditLog, User

logger = logging.getLogger(__name__)


class AuditAction:
    """Canonical audit action names (kept as constants, not an enum, so new
    actions can be added without a database migration)."""

    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGIN_DENIED = "auth.login.denied"
    LOGIN_THROTTLED = "auth.login.throttled"
    LOGOUT = "auth.logout"
    LOGOUT_ALL = "auth.logout_all"
    SESSIONS_LISTED = "auth.sessions.listed"
    SESSION_REVOKED = "auth.session.revoked"
    PERMISSION_DENIED = "authz.denied"

    QUERY_RECEIVED = "chat.query.received"
    QUERY_ANSWERED = "chat.query.answered"
    QUERY_BLOCKED = "chat.query.blocked"

    CONVERSATION_CREATED = "chat.conversation.created"
    CONVERSATION_DENIED = "chat.conversation.denied"
    CONVERSATION_DELETED = "chat.conversation.deleted"

    RETRIEVAL_PERFORMED = "rag.retrieval.performed"
    RETRIEVAL_DENIED = "rag.retrieval.denied"

    KNOWLEDGE_LISTED = "knowledge.documents.listed"
    DOCUMENT_VIEWED = "knowledge.document.viewed"
    DOCUMENT_ACCESS_DENIED = "knowledge.document.denied"
    REINDEX_PERFORMED = "knowledge.reindex.performed"
    REINDEX_DENIED = "knowledge.reindex.denied"

    TICKET_CREATED = "ticket.created"
    TICKET_VIEWED = "ticket.viewed"
    TICKET_LISTED = "ticket.listed"
    TICKET_LIST_DENIED = "ticket.list.denied"
    TICKET_ACCESS_DENIED = "ticket.access.denied"
    TICKET_STATUS_CHANGED = "ticket.status_changed"
    TICKET_STATUS_DENIED = "ticket.status.denied"
    TICKET_NOTE_ADDED = "ticket.note.added"
    TICKET_SUGGESTED = "ticket.suggested"
    TICKET_ESCALATED = "ticket.escalated"

    ESCALATION_TRIGGERED = "escalation.triggered"

    DASHBOARD_VIEWED = "dashboard.viewed"

    SEED_EXECUTED = "admin.seed.executed"


def record_audit(
    session: Session,
    *,
    action: str,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    actor: User | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
    commit: bool = False,
) -> AuditLog | None:
    """Insert one audit row.

    ``detail`` must contain metadata only - never secrets, tokens, passwords or
    full document bodies.
    """
    try:
        entry = AuditLog(
            created_at=dt.datetime.now(dt.UTC),
            actor_user_id=getattr(actor, "id", None),
            actor_email=getattr(actor, "email", None),
            actor_role=getattr(getattr(actor, "role", None), "value", None),
            action=action,
            resource_type=resource_type,
            resource_id=None if resource_id is None else str(resource_id),
            outcome=outcome,
            request_id=request_id_var.get(),
            ip_address=ip_address,
            detail=detail or None,
        )
        session.add(entry)
        if commit:
            session.commit()
        return entry
    except Exception:  # pragma: no cover - audit must never break the request
        logger.exception("audit_write_failed action=%s", action)
        return None
