"""Ticket service: creation, scoped reads, and status transitions.

Two rules shape this module:

* **Visibility is decided by the shared policy.** ``app.security.rbac`` owns the
  ticket rules; this service only applies the filter it returns. A ticket the
  caller may not see is reported as missing, so ticket references cannot be
  probed.
* **Transitions are validated, and a serious ticket cannot be closed quietly.**
  A ticket that required a human escalation must be acknowledged before it can be
  resolved, and every change is written to an append-only timeline.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.enums import Role, Severity, TicketSource, TicketStatus
from app.core.errors import NotFoundError, PermissionDeniedError, ValidationError
from app.db.models import Message, Ticket, TicketEvent, User
from app.security.rbac import can_update_ticket, can_view_ticket, visible_ticket_filter
from app.security.redaction import redact_credentials

logger = logging.getLogger(__name__)

MAX_TITLE_CHARS = 200
MAX_DESCRIPTION_CHARS = 8000
MAX_NOTE_CHARS = 2000
MAX_RELATED_QUERY_CHARS = 1000
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

#: Prefix per owning role. Used for the human-readable reference.
REFERENCE_PREFIX: dict[Role, str] = {
    Role.EMPLOYEE: "REQ",
    Role.IT: "IT",
    Role.SECURITY: "SEC",
}

#: Which statuses a ticket may move to from each status.
#:
#: ``closed`` is terminal: reopening a closed ticket would need a new record so
#: that the closure decision stays auditable.
ALLOWED_TRANSITIONS: dict[TicketStatus, frozenset[TicketStatus]] = {
    TicketStatus.OPEN: frozenset(
        {
            TicketStatus.IN_PROGRESS,
            TicketStatus.ESCALATED,
            TicketStatus.RESOLVED,
            TicketStatus.CLOSED,
        }
    ),
    TicketStatus.IN_PROGRESS: frozenset(
        {TicketStatus.ESCALATED, TicketStatus.RESOLVED, TicketStatus.CLOSED, TicketStatus.OPEN}
    ),
    TicketStatus.ESCALATED: frozenset(
        {TicketStatus.IN_PROGRESS, TicketStatus.RESOLVED, TicketStatus.CLOSED}
    ),
    TicketStatus.RESOLVED: frozenset({TicketStatus.CLOSED, TicketStatus.IN_PROGRESS}),
    TicketStatus.CLOSED: frozenset(),
}

#: Statuses that count as "a human has picked this up".
ACKNOWLEDGED_STATUSES = frozenset({TicketStatus.IN_PROGRESS, TicketStatus.ESCALATED})


class TicketValidationError(ValidationError):
    code = "ticket_validation_error"


def build_reference(prefix: str, year: int, sequence: int) -> str:
    """``SEC-2024-0007`` - the human-facing identifier."""
    return f"{prefix}-{year}-{sequence:04d}"


class TicketService:
    """Ticket operations for one request at a time."""

    # -- creation ---------------------------------------------------------
    def next_reference(
        self, session: Session, *, owner_role: Role, now: dt.datetime | None = None
    ) -> str:
        """Allocate the next reference for this role and year.

        The unique constraint on ``reference`` is the real guarantee: if two
        workers allocate the same value the insert fails and the caller retries,
        rather than silently producing two tickets with one identifier.
        """
        now = now or dt.datetime.now(dt.UTC)
        prefix = REFERENCE_PREFIX[owner_role]
        pattern = f"{prefix}-{now.year}-%"
        existing = session.scalar(
            select(func.count(Ticket.id)).where(Ticket.reference.like(pattern))
        )
        return build_reference(prefix, now.year, int(existing or 0) + 1)

    def create_ticket(
        self,
        session: Session,
        *,
        title: str,
        description: str = "",
        severity: Severity = Severity.LOW,
        status: TicketStatus = TicketStatus.OPEN,
        category: str = "security",
        owner_role: Role = Role.SECURITY,
        source: TicketSource = TicketSource.AI_AUTO,
        created_by: User | None = None,
        conversation_id: int | None = None,
        related_query: str = "",
        escalation_required: bool = False,
        automated: bool = False,
        note: str = "",
    ) -> Ticket:
        """Create a ticket and its first timeline entry."""
        # Ticket text is copied from what the user wrote, and users paste
        # credentials into chat when reporting an incident. Redact before it is
        # stored: a ticket outlives the conversation and reaches more readers.
        cleaned_title = redact_credentials(title).strip()[:MAX_TITLE_CHARS]
        if not cleaned_title:
            raise TicketValidationError("A ticket needs a title.")
        if escalation_required and status is TicketStatus.CLOSED:
            raise TicketValidationError("An escalated ticket cannot be created closed.")

        ticket = Ticket(
            reference=self.next_reference(session, owner_role=owner_role),
            title=cleaned_title,
            description=redact_credentials(description).strip()[:MAX_DESCRIPTION_CHARS],
            category=category[:64],
            severity=severity,
            status=status,
            source=source,
            escalation_required=escalation_required,
            created_by_user_id=created_by.id if created_by else None,
            owner_role=owner_role,
            conversation_id=conversation_id,
            related_query=redact_credentials(related_query).strip()[:MAX_RELATED_QUERY_CHARS],
        )
        session.add(ticket)
        session.flush()

        self.record_event(
            session,
            ticket,
            event_type="created",
            actor=created_by,
            automated=automated,
            to_status=status.value,
            to_severity=severity.value,
            note=note or f"Ticket created from {source.value}.",
        )
        logger.info(
            "ticket_created reference=%s severity=%s status=%s owner=%s source=%s",
            ticket.reference,
            severity.value,
            status.value,
            owner_role.value,
            source.value,
        )
        return ticket

    # -- reads ------------------------------------------------------------
    def _visible_scope(self, *, user: User) -> list[Any]:
        """The predicates describing what this principal may read.

        One definition, used by the list *and* by the counts, so the numbers on the
        page can never disagree with the rows beneath them.
        """
        criteria = visible_ticket_filter(user.role, user.id)

        created_by = criteria.get("created_by_user_id")
        owner_roles = criteria.get("owner_roles")
        if created_by is not None and owner_roles:
            # IT: their own tickets plus everything their team is responsible for.
            return [
                or_(
                    Ticket.created_by_user_id == created_by,
                    Ticket.owner_role.in_(owner_roles),
                )
            ]
        if created_by is not None:
            return [Ticket.created_by_user_id == created_by]
        return []

    def list_visible(
        self,
        session: Session,
        *,
        user: User,
        status: TicketStatus | None = None,
        severity: Severity | None = None,
        owner_role: Role | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> list[Ticket]:
        """Tickets this user may see, newest first.

        The scope comes from the shared policy, so the database does the
        filtering rather than a post-filter in Python.
        """
        statement = select(Ticket).where(*self._visible_scope(user=user))

        if status is not None:
            statement = statement.where(Ticket.status == status)
        if severity is not None:
            statement = statement.where(Ticket.severity == severity)
        if owner_role is not None:
            statement = statement.where(Ticket.owner_role == owner_role)

        statement = (
            statement.order_by(Ticket.created_at.desc(), Ticket.id.desc())
            .limit(max(1, min(limit, MAX_PAGE_SIZE)))
            .offset(max(0, offset))
        )
        return list(session.scalars(statement).all())

    def count_visible(self, session: Session, *, user: User) -> int:
        """How many tickets this user can see, counted in SQL.

        It used to fetch up to `MAX_PAGE_SIZE` rows and take their length, which is
        a silent wrong answer past 200 tickets: the oldest rows simply stopped
        existing for the counter.
        """
        return int(
            session.scalar(
                select(func.count()).select_from(Ticket).where(*self._visible_scope(user=user))
            )
            or 0
        )

    def get_visible(self, session: Session, *, user: User, reference: str) -> Ticket:
        """Fetch a ticket by reference, or report it missing.

        A ticket the caller may not see is *not found*, not *forbidden*: a
        distinct 403 would confirm that the reference exists.
        """
        ticket = session.scalar(select(Ticket).where(Ticket.reference == reference))
        if ticket is None:
            raise NotFoundError("Ticket not found.")
        if not self.can_view(user=user, ticket=ticket):
            logger.info(
                "ticket_access_denied reference=%s user_id=%s role=%s",
                reference,
                user.id,
                user.role.value,
            )
            raise NotFoundError("Ticket not found.")
        return ticket

    @staticmethod
    def can_view(*, user: User, ticket: Ticket) -> bool:
        return can_view_ticket(
            role=user.role,
            user_id=user.id,
            ticket_owner_role=ticket.owner_role,
            ticket_created_by_user_id=ticket.created_by_user_id,
        )

    @staticmethod
    def can_update(*, user: User, ticket: Ticket) -> bool:
        return can_update_ticket(
            role=user.role,
            user_id=user.id,
            ticket_owner_role=ticket.owner_role,
            ticket_created_by_user_id=ticket.created_by_user_id,
        )

    def timeline(self, session: Session, ticket: Ticket) -> list[TicketEvent]:
        return list(
            session.scalars(
                select(TicketEvent)
                .where(TicketEvent.ticket_id == ticket.id)
                .order_by(TicketEvent.id.asc())
            ).all()
        )

    def find_open_for_conversation(
        self, session: Session, *, conversation_id: int
    ) -> Ticket | None:
        """The newest live ticket raised from a conversation.

        Used to escalate an existing ticket rather than opening a second one when
        the same situation gets worse.
        """
        return session.scalar(
            select(Ticket)
            .where(
                Ticket.conversation_id == conversation_id,
                Ticket.status.notin_([TicketStatus.RESOLVED, TicketStatus.CLOSED]),
            )
            .order_by(Ticket.id.desc())
        )

    # -- writes -----------------------------------------------------------
    def change_status(
        self,
        session: Session,
        *,
        user: User,
        ticket: Ticket,
        new_status: TicketStatus,
        note: str = "",
        automated: bool = False,
    ) -> Ticket:
        """Move a ticket to a new status, if the caller and the rules allow it."""
        if not automated and not self.can_update(user=user, ticket=ticket):
            raise PermissionDeniedError("You do not have permission to change this ticket.")

        if new_status is ticket.status:
            raise TicketValidationError(f"The ticket is already {new_status.value}.")

        allowed = ALLOWED_TRANSITIONS[ticket.status]
        if new_status not in allowed:
            raise TicketValidationError(
                f"A ticket cannot move from {ticket.status.value} to {new_status.value}."
            )

        # A ticket that needed a human must be picked up before it can be closed:
        # otherwise an escalation could be dismissed without anybody seeing it.
        if (
            ticket.escalation_required
            and new_status in {TicketStatus.RESOLVED, TicketStatus.CLOSED}
            and ticket.status not in ACKNOWLEDGED_STATUSES
        ):
            raise TicketValidationError(
                "This ticket requires a human response, so it must be acknowledged "
                "(in progress or escalated) before it can be resolved."
            )

        previous = ticket.status
        ticket.status = new_status
        ticket.updated_at = dt.datetime.now(dt.UTC)
        if new_status is TicketStatus.ESCALATED:
            ticket.escalation_required = True

        self.record_event(
            session,
            ticket,
            event_type="status_changed",
            actor=user,
            automated=automated,
            from_status=previous.value,
            to_status=new_status.value,
            note=note.strip()[:MAX_NOTE_CHARS],
        )
        logger.info(
            "ticket_status_changed reference=%s from=%s to=%s by=%s",
            ticket.reference,
            previous.value,
            new_status.value,
            "system" if automated else user.role.value,
        )
        return ticket

    def escalate(
        self,
        session: Session,
        *,
        ticket: Ticket,
        severity: Severity,
        reason: str,
        user: User | None = None,
        automated: bool = True,
    ) -> Ticket:
        """Raise a ticket's severity and put it in the human queue."""
        previous_severity = ticket.severity
        previous_status = ticket.status

        if severity.rank > ticket.severity.rank:
            ticket.severity = severity
        ticket.escalation_required = True
        if ticket.status not in {TicketStatus.RESOLVED, TicketStatus.CLOSED}:
            ticket.status = TicketStatus.ESCALATED
        ticket.updated_at = dt.datetime.now(dt.UTC)

        if ticket.severity is not previous_severity:
            self.record_event(
                session,
                ticket,
                event_type="severity_changed",
                actor=user,
                automated=automated,
                from_severity=previous_severity.value,
                to_severity=ticket.severity.value,
                note=reason[:MAX_NOTE_CHARS],
            )
        if ticket.status is not previous_status:
            self.record_event(
                session,
                ticket,
                event_type="status_changed",
                actor=user,
                automated=automated,
                from_status=previous_status.value,
                to_status=ticket.status.value,
                note=reason[:MAX_NOTE_CHARS],
            )
        # The `escalated` event is evidence of a *change*: a ticket that was already
        # escalated, at the same severity and status, has not been escalated again.
        # Recording it per turn filled the timeline with identical entries - measured,
        # four `escalated` events for one ticket after three harmless follow-up questions
        # - which makes the timeline a worse record, not a richer one.
        changed = ticket.severity is not previous_severity or ticket.status is not previous_status
        if changed:
            self.record_event(
                session,
                ticket,
                event_type="escalated",
                actor=user,
                automated=automated,
                note=reason[:MAX_NOTE_CHARS],
            )
        logger.warning(
            "ticket_escalated reference=%s severity=%s changed=%s reason=%s",
            ticket.reference,
            ticket.severity.value,
            changed,
            reason[:80],
        )
        return ticket

    def add_note(self, session: Session, *, user: User, ticket: Ticket, note: str) -> TicketEvent:
        """Append a comment. Anyone who can see the ticket may comment on it."""
        text = redact_credentials(note).strip()[:MAX_NOTE_CHARS]
        if not text:
            raise TicketValidationError("A note must not be empty.")
        return self.record_event(
            session,
            ticket,
            event_type="note",
            actor=user,
            automated=False,
            note=text,
        )

    @staticmethod
    def record_event(
        session: Session,
        ticket: Ticket,
        *,
        event_type: str,
        actor: User | None = None,
        automated: bool = False,
        from_status: str | None = None,
        to_status: str | None = None,
        from_severity: str | None = None,
        to_severity: str | None = None,
        note: str = "",
    ) -> TicketEvent:
        event = TicketEvent(
            ticket_id=ticket.id,
            created_at=dt.datetime.now(dt.UTC),
            event_type=event_type[:32],
            from_status=from_status,
            to_status=to_status,
            from_severity=from_severity,
            to_severity=to_severity,
            actor_user_id=actor.id if actor else None,
            actor_role=actor.role.value if actor else None,
            automated=automated,
            note=note,
        )
        session.add(event)
        session.flush()
        return event

    # -- helpers ----------------------------------------------------------
    def conversation_excerpt(
        self, session: Session, *, conversation_id: int, limit: int = 4
    ) -> str:
        """A short transcript to give the security team context.

        Only the user's own questions and the assistant's answers from that
        conversation - and the conversation already belongs to the caller, so
        nothing outside their scope can end up in the ticket.
        """
        rows: Sequence[Message] = session.scalars(
            select(Message)
            .where(Message.conversation_id == conversation_id)
            .order_by(Message.id.asc())
            .limit(limit)
        ).all()
        lines = [
            f"{'User' if row.role.value == 'user' else 'Assistant'}: "
            f"{' '.join(row.content.split())[:300]}"
            for row in rows
        ]
        return "\n".join(lines)[:2000]

    def statistics(self, session: Session, *, user: User) -> dict[str, Any]:
        """Counts for the tickets this user can see. No ticket content.

        Every number is a SQL aggregate over the caller's own visibility scope
        (`_visible_scope`), not a tally of a fetched page. The page-capped version
        was wrong in two ways: past 200 tickets every figure was silently truncated
        (the *oldest* rows vanished first, because the page is ordered newest-first),
        and it did the counting in Python after moving rows over the wire.
        """
        scope = self._visible_scope(user=user)

        def count(*extra: Any) -> int:
            statement = select(func.count()).select_from(Ticket).where(*scope, *extra)
            return int(session.scalar(statement) or 0)

        def group(column: Any) -> dict[str, int]:
            rows = session.execute(
                select(column, func.count()).select_from(Ticket).where(*scope).group_by(column)
            ).all()
            return {str(key.value if hasattr(key, "value") else key): int(value) for key, value in rows}

        by_status = {status.value: 0 for status in TicketStatus}
        by_status.update(group(Ticket.status))
        by_severity = {severity.value: 0 for severity in Severity}
        by_severity.update(group(Ticket.severity))

        return {
            "total": count(),
            "open": count(Ticket.status.in_([s for s in TicketStatus if not s.is_terminal])),
            "escalated": by_status[TicketStatus.ESCALATED.value],
            "requiring_human": count(Ticket.escalation_required.is_(True)),
            "by_status": by_status,
            "by_severity": by_severity,
        }
