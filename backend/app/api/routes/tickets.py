"""Ticket endpoints.

Access is decided by the shared policy in ``app.security.rbac``: a ticket the
caller may not see is reported as *not found*, and a caller who may read but not
write is refused with a permission error and an audit entry.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query, Request, status

from app.api.deps import CurrentUser, DbSession, client_ip
from app.core.enums import AuditOutcome, Role, Severity, TicketSource, TicketStatus
from app.core.errors import NotFoundError, PermissionDeniedError, ValidationError
from app.db.models import Ticket
from app.schemas.ticket import (
    AddNoteRequest,
    CreateTicketRequest,
    TicketDetail,
    TicketEventOut,
    TicketListResponse,
    TicketStatisticsResponse,
    TicketSummary,
    UpdateTicketRequest,
)
from app.security.audit import AuditAction, record_audit
from app.services.ticket_service import TicketService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tickets", tags=["tickets"])

#: Which team a self-raised ticket goes to, by the raiser's role. Used when the
#: category does not name a security matter.
OWNER_ROLE_FOR_RAISER: dict[Role, Role] = {
    Role.EMPLOYEE: Role.IT,
    Role.IT: Role.IT,
    Role.SECURITY: Role.SECURITY,
}

#: Categories a user raises that belong to the security queue. The UI sends
#: `security` for anything that is not an IT request, and `phishing`/`incident`
#: when the assistant classified the message that way.
SECURITY_CATEGORIES = frozenset(
    {"security", "incident", "phishing", "malware", "ransomware", "data_leak", "data_loss", "access"}
)

#: Severity for a ticket a user raises themselves. Deliberately never high or
#: critical: urgency is the security team's judgement, not the reporter's, and the
#: chat path is what raises severity when the assessment warrants it. A security
#: report is medium rather than low, though - it is not a routine request.
SEVERITY_FOR_SELF_RAISED = {
    Role.SECURITY: Severity.MEDIUM,
    Role.IT: Severity.LOW,
    Role.EMPLOYEE: Severity.LOW,
}


def get_ticket_service(request: Request) -> TicketService:
    service = getattr(request.app.state, "tickets", None)
    if service is None:
        service = TicketService()
        request.app.state.tickets = service
    return service


def _iso(value: object) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else None


def to_summary(ticket: Ticket) -> TicketSummary:
    return TicketSummary(
        reference=ticket.reference,
        title=ticket.title,
        category=ticket.category,
        severity=ticket.severity.value,
        status=ticket.status.value,
        source=ticket.source.value,
        owner_role=ticket.owner_role.value,
        escalation_required=ticket.escalation_required,
        created_at=_iso(ticket.created_at),
        updated_at=_iso(ticket.updated_at),
    )


@router.get("", response_model=TicketListResponse, summary="Tickets visible to the caller")
def list_tickets(
    request: Request,
    user: CurrentUser,
    session: DbSession,
    status_filter: TicketStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = Query(default=None),
    owner_role: Role | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> TicketListResponse:
    service = get_ticket_service(request)
    tickets = service.list_visible(
        session,
        user=user,
        status=status_filter,
        severity=severity,
        owner_role=owner_role,
        limit=limit,
        offset=offset,
    )
    record_audit(
        session,
        action=AuditAction.TICKET_LISTED,
        actor=user,
        resource_type="ticket",
        detail={"role": user.role.value, "returned": len(tickets), "filters": bool(status_filter)},
        ip_address=client_ip(request),
        commit=True,
    )
    return TicketListResponse(
        count=len(tickets),
        statistics=service.statistics(session, user=user),
        tickets=[to_summary(ticket) for ticket in tickets],
    )


@router.get(
    "/statistics",
    response_model=TicketStatisticsResponse,
    summary="Ticket counts for the caller's scope",
)
def ticket_statistics(
    request: Request, user: CurrentUser, session: DbSession
) -> TicketStatisticsResponse:
    """Counts only - never ticket titles, references or content."""
    return TicketStatisticsResponse(
        statistics=get_ticket_service(request).statistics(session, user=user)
    )


@router.post(
    "",
    response_model=TicketDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Raise a ticket yourself",
)
def create_ticket(
    payload: CreateTicketRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> TicketDetail:
    """Create a ticket the user asked for.

    The owning team comes from the **category**, and the severity from the owning
    team - never from the request body, which still cannot set either. Deriving the
    owner from the *raiser's role* alone was a workflow dead end on the product's
    flagship path: the UI posts `category: 'security'` for anything the assistant
    did not classify as IT support, and an employee reporting a security concern got
    an IT queue, `low` severity, and `can_update: false` - so the security team might
    never triage it and the reporter could not follow it up.

    What a caller cannot do is unchanged: `severity`, `owner_role`, `status`,
    `source` and `escalation_required` in the body are ignored (the request schema
    does not even declare them), so self-inflicted urgency is impossible.
    """
    service = get_ticket_service(request)
    category = (payload.category or "").strip().lower()
    is_security = category in SECURITY_CATEGORIES
    owner_role = Role.SECURITY if is_security else OWNER_ROLE_FOR_RAISER[user.role]

    ticket = service.create_ticket(
        session,
        title=payload.title,
        description=payload.description,
        category=category or "other",
        severity=Severity.MEDIUM if is_security else SEVERITY_FOR_SELF_RAISED[user.role],
        status=TicketStatus.OPEN,
        owner_role=owner_role,
        source=TicketSource.USER_REQUEST,
        created_by=user,
        escalation_required=False,
        automated=False,
        note=(
            "Raised by the user as a security report."
            if is_security
            else "Raised by the user."
        ),
    )
    record_audit(
        session,
        action=AuditAction.TICKET_CREATED,
        actor=user,
        resource_type="ticket",
        resource_id=ticket.reference,
        detail={
            "source": ticket.source.value,
            "owner_role": ticket.owner_role.value,
            "category": ticket.category,
            "severity": ticket.severity.value,
        },
        ip_address=client_ip(request),
        commit=True,
    )
    return _detail(service, session, ticket, user=user)


@router.get(
    "/{reference}",
    response_model=TicketDetail,
    summary="Read one ticket",
)
def get_ticket(
    reference: str,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> TicketDetail:
    service = get_ticket_service(request)
    try:
        ticket = service.get_visible(session, user=user, reference=reference)
    except NotFoundError:
        record_audit(
            session,
            action=AuditAction.TICKET_ACCESS_DENIED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="ticket",
            resource_id=reference,
            detail={"role": user.role.value},
            ip_address=client_ip(request),
            commit=True,
        )
        raise
    record_audit(
        session,
        action=AuditAction.TICKET_VIEWED,
        actor=user,
        resource_type="ticket",
        resource_id=ticket.reference,
        detail={"role": user.role.value},
        ip_address=client_ip(request),
        commit=True,
    )
    return _detail(service, session, ticket, user=user)


@router.patch(
    "/{reference}",
    response_model=TicketDetail,
    summary="Change a ticket's status",
)
def update_ticket(
    reference: str,
    payload: UpdateTicketRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> TicketDetail:
    service = get_ticket_service(request)
    ticket = service.get_visible(session, user=user, reference=reference)

    try:
        target = TicketStatus(payload.status.lower())
    except ValueError as exc:
        raise ValidationError(
            f"Unknown status. Expected one of: {[s.value for s in TicketStatus]}."
        ) from exc

    if not service.can_update(user=user, ticket=ticket):
        record_audit(
            session,
            action=AuditAction.TICKET_STATUS_DENIED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="ticket",
            resource_id=ticket.reference,
            detail={"role": user.role.value, "attempted_status": target.value},
            ip_address=client_ip(request),
            commit=True,
        )
        raise PermissionDeniedError("You do not have permission to change this ticket.")

    previous = ticket.status.value
    service.change_status(session, user=user, ticket=ticket, new_status=target, note=payload.note)
    record_audit(
        session,
        action=AuditAction.TICKET_STATUS_CHANGED,
        actor=user,
        resource_type="ticket",
        resource_id=ticket.reference,
        detail={"from": previous, "to": target.value},
        ip_address=client_ip(request),
        commit=True,
    )
    return _detail(service, session, ticket, user=user)


@router.post(
    "/{reference}/notes",
    response_model=TicketDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Add a note to a ticket",
)
def add_note(
    reference: str,
    payload: AddNoteRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> TicketDetail:
    """Anyone who can read the ticket may comment on it."""
    service = get_ticket_service(request)
    ticket = service.get_visible(session, user=user, reference=reference)
    service.add_note(session, user=user, ticket=ticket, note=payload.note)
    record_audit(
        session,
        action=AuditAction.TICKET_NOTE_ADDED,
        actor=user,
        resource_type="ticket",
        resource_id=ticket.reference,
        detail={"note_chars": len(payload.note)},
        ip_address=client_ip(request),
        commit=True,
    )
    return _detail(service, session, ticket, user=user)


def _detail(
    service: TicketService, session: DbSession, ticket: Ticket, *, user: CurrentUser
) -> TicketDetail:
    summary = to_summary(ticket)
    return TicketDetail(
        **summary.model_dump(),
        description=ticket.description,
        related_query=ticket.related_query,
        can_update=service.can_update(user=user, ticket=ticket),
        events=[
            TicketEventOut(
                id=event.id,
                created_at=_iso(event.created_at),
                event_type=event.event_type,
                from_status=event.from_status,
                to_status=event.to_status,
                from_severity=event.from_severity,
                to_severity=event.to_severity,
                actor_role=event.actor_role,
                automated=event.automated,
                note=event.note,
            )
            for event in service.timeline(session, ticket)
        ],
    )
