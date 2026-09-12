"""Security dashboard endpoints.

Restricted to the security role: this is the "administrator" view the
specification asks for, and it aggregates activity across every user. The role
check goes through the shared authorization dependency, so a denial is audited
like any other.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from app.api.deps import CurrentUser, DbSession, client_ip, require_roles
from app.core.enums import Role
from app.db.models import User
from app.schemas.dashboard import (
    AuditActionsResponse,
    AuditLogResponse,
    DashboardOverview,
    DashboardSummary,
    DistributionsResponse,
    DocumentAccessResponse,
    ResponseTimesResponse,
    TimeseriesResponse,
)
from app.security.audit import AuditAction, record_audit
from app.services.dashboard_service import (
    DEFAULT_WINDOW_DAYS,
    MAX_WINDOW_DAYS,
    AuditQuery,
    DashboardService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

#: Every route in this file is behind this dependency.
SecurityUser = Annotated[User, Depends(require_roles(Role.SECURITY))]

WindowDays = Annotated[int, Query(ge=1, le=MAX_WINDOW_DAYS, description="Look-back window")]


def get_dashboard_service(request: Request) -> DashboardService:
    service = getattr(request.app.state, "dashboard", None)
    if service is None:
        service = DashboardService()
        request.app.state.dashboard = service
    return service


def _note_view(request: Request, session: DbSession, user: User, view: str) -> None:
    record_audit(
        session,
        action=AuditAction.DASHBOARD_VIEWED,
        actor=user,
        resource_type="dashboard",
        resource_id=view,
        detail={"role": user.role.value},
        ip_address=client_ip(request),
        commit=True,
    )


@router.get("/overview", response_model=DashboardOverview, summary="Everything the dashboard shows")
def overview(
    request: Request,
    session: DbSession,
    user: SecurityUser,
    days: WindowDays = DEFAULT_WINDOW_DAYS,
) -> DashboardOverview:
    """One round trip for the whole dashboard.

    Returns counts and aggregates only - no conversation text, no answer content,
    no document bodies.
    """
    service = get_dashboard_service(request)
    _note_view(request, session, user, "overview")
    return DashboardOverview(**service.overview(session, days=days))


@router.get("/summary", response_model=DashboardSummary, summary="Headline counters")
def summary(
    request: Request,
    session: DbSession,
    user: SecurityUser,
    days: WindowDays = DEFAULT_WINDOW_DAYS,
) -> DashboardSummary:
    service = get_dashboard_service(request)
    _note_view(request, session, user, "summary")
    return DashboardSummary(**service.summary(session, days=days))


@router.get("/timeseries", response_model=TimeseriesResponse, summary="Daily activity")
def timeseries(
    request: Request,
    session: DbSession,
    user: SecurityUser,
    days: WindowDays = DEFAULT_WINDOW_DAYS,
) -> TimeseriesResponse:
    service = get_dashboard_service(request)
    _note_view(request, session, user, "timeseries")
    return TimeseriesResponse(**service.timeseries(session, days=days))


@router.get(
    "/distributions",
    response_model=DistributionsResponse,
    summary="Breakdown by classification and ticket state",
)
def distributions(
    request: Request,
    session: DbSession,
    user: SecurityUser,
    days: WindowDays = DEFAULT_WINDOW_DAYS,
) -> DistributionsResponse:
    service = get_dashboard_service(request)
    _note_view(request, session, user, "distributions")
    return DistributionsResponse(**service.distributions(session, days=days))


@router.get(
    "/response-times",
    response_model=ResponseTimesResponse,
    summary="How long escalated tickets waited for a human",
)
def response_times(
    request: Request,
    session: DbSession,
    user: SecurityUser,
    days: WindowDays = DEFAULT_WINDOW_DAYS,
) -> ResponseTimesResponse:
    service = get_dashboard_service(request)
    _note_view(request, session, user, "response_times")
    return ResponseTimesResponse(**service.response_times(session, days=days))


@router.get(
    "/document-access",
    response_model=DocumentAccessResponse,
    summary="Which documents were read, and which attempts were refused",
)
def document_access(
    request: Request,
    session: DbSession,
    user: SecurityUser,
    days: WindowDays = DEFAULT_WINDOW_DAYS,
) -> DocumentAccessResponse:
    service = get_dashboard_service(request)
    _note_view(request, session, user, "document_access")
    return DocumentAccessResponse(**service.document_access(session, days=days))


@router.get("/audit", response_model=AuditLogResponse, summary="Search the audit trail")
def audit_log(
    request: Request,
    session: DbSession,
    user: SecurityUser,
    action: Annotated[str | None, Query(max_length=64)] = None,
    actor_role: Annotated[str | None, Query(max_length=32)] = None,
    outcome: Annotated[str | None, Query(max_length=16)] = None,
    days: WindowDays = DEFAULT_WINDOW_DAYS,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditLogResponse:
    """Metadata-only search over the audit trail.

    The stored ``detail`` blob is represented by its key names rather than its
    values, so this endpoint cannot become a bulk export of application data.
    """
    service = get_dashboard_service(request)
    _note_view(request, session, user, "audit")
    result = service.audit_log(
        session,
        AuditQuery(
            action=action,
            actor_role=actor_role,
            outcome=outcome,
            since_days=days,
            limit=limit,
            offset=offset,
        ),
    )
    return AuditLogResponse(**result)


@router.get(
    "/audit/actions",
    response_model=AuditActionsResponse,
    summary="Distinct audit actions, for the filter list",
)
def audit_actions(request: Request, session: DbSession, user: SecurityUser) -> AuditActionsResponse:
    _note_view(request, session, user, "audit_actions")
    return AuditActionsResponse(actions=get_dashboard_service(request).audit_actions(session))


@router.get("/capabilities", summary="What the dashboard covers")
def capabilities(_: CurrentUser) -> dict[str, object]:
    """Available to any authenticated role: it describes the dashboard, not its data."""
    return {
        "available_to": ["security"],
        "views": [
            "summary",
            "timeseries",
            "distributions",
            "response_times",
            "document_access",
            "audit",
        ],
        "max_window_days": MAX_WINDOW_DAYS,
        "returns_content": False,
    }
