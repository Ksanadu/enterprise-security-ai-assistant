"""Authentication endpoints.

Sign-in issues a short-lived access token **and** records it server-side, so it
can be revoked. Sign-out revokes it. Every attempt is throttled and audited.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response, status

from app.api.deps import AppSettings, CurrentUser, DbSession, client_ip, current_session_jti
from app.core.enums import AuditOutcome
from app.core.errors import RateLimitError
from app.core.security import create_access_token
from app.db.models import User
from app.schemas.auth import (
    LoginRequest,
    SessionInfo,
    SessionListResponse,
    TokenResponse,
    UserPublic,
)
from app.security.audit import AuditAction, record_audit
from app.security.login_guard import LoginGuard
from app.security.sessions import (
    REASON_LOGOUT,
    REASON_LOGOUT_ALL,
    list_active_sessions,
    record_session,
    revoke_all_for_user,
    revoke_session,
)
from app.services.auth_service import authenticate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def get_login_guard(request: Request, settings: AppSettings) -> LoginGuard:
    """One guard per application, so counters survive across requests."""
    guard = getattr(request.app.state, "login_guard", None)
    if guard is None:
        guard = LoginGuard(
            max_attempts=settings.auth_max_login_attempts,
            window_seconds=settings.auth_login_window_seconds,
            lockout_seconds=settings.auth_lockout_seconds,
            ip_max_attempts=settings.auth_max_login_attempts_per_ip,
        )
        request.app.state.login_guard = guard
    return guard


def to_public(user: User) -> UserPublic:
    """Project an ORM user onto the safe public representation."""
    return UserPublic(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        role_label=user.role.label,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Exchange credentials for an access token",
)
def login(
    payload: LoginRequest,
    request: Request,
    session: DbSession,
    settings: AppSettings,
) -> TokenResponse:
    guard = get_login_guard(request, settings)
    email = str(payload.email)
    ip = client_ip(request)

    # Refuse before the expensive bcrypt work, and refuse *before* the credential
    # check so a correct password during a lockout is still rejected - otherwise
    # the lockout would be trivial to bypass.
    if guard.is_locked(email=email, ip_address=ip):
        record_audit(
            session,
            action=AuditAction.LOGIN_THROTTLED,
            outcome=AuditOutcome.DENIED,
            resource_type="user",
            detail={"reason": "lockout_active"},
            ip_address=ip,
            commit=True,
        )
        raise RateLimitError(
            "Too many failed sign-in attempts. Please wait and try again.",
            details={"retry_after_seconds": int(guard.lockout_seconds())},
        )

    try:
        user = authenticate(session, email=email, password=payload.password, ip_address=ip)
    except Exception:
        # Count the failure, then re-raise: the caller still receives the generic
        # "invalid email or password" response, so lockout is not an oracle.
        guard.record_failure(email=email, ip_address=ip)
        raise

    guard.record_success(email=email, ip_address=ip)

    issued = create_access_token(subject=str(user.id), role=user.role.value, settings=settings)
    record_session(
        session,
        user_id=user.id,
        jti=issued.jti,
        expires_at=issued.expires_at,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )
    session.commit()

    return TokenResponse(
        access_token=issued.token,
        expires_in=issued.expires_in,
        user=to_public(user),
    )


@router.get("/me", response_model=UserPublic, summary="Current authenticated user")
def me(user: CurrentUser) -> UserPublic:
    return to_public(user)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Revoke the current access token",
)
def logout(
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> Response:
    """Revoke this session server-side.

    A client that simply discards the token leaves it usable until it expires;
    revoking makes sign-out immediate.
    """
    jti = current_session_jti(request)
    if jti is not None:
        revoke_session(session, jti=jti, reason=REASON_LOGOUT)
    record_audit(
        session,
        action=AuditAction.LOGOUT,
        actor=user,
        resource_type="user_session",
        resource_id=jti,
        ip_address=client_ip(request),
        commit=True,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/logout-all",
    summary="Revoke every session for the current user",
)
def logout_all(
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> dict[str, int]:
    """Sign out everywhere. Useful after a suspected credential compromise."""
    revoked = revoke_all_for_user(session, user_id=user.id, reason=REASON_LOGOUT_ALL)
    record_audit(
        session,
        action=AuditAction.LOGOUT_ALL,
        actor=user,
        resource_type="user",
        resource_id=user.id,
        detail={"revoked": revoked},
        ip_address=client_ip(request),
        commit=True,
    )
    return {"revoked": revoked}


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="List the caller's active sessions",
)
def sessions(
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> SessionListResponse:
    """Show where the account is signed in. Only the caller's own sessions."""
    current = current_session_jti(request)
    records = list_active_sessions(session, user_id=user.id)
    record_audit(
        session,
        action=AuditAction.SESSIONS_LISTED,
        actor=user,
        resource_type="user",
        resource_id=user.id,
        detail={"count": len(records)},
        ip_address=client_ip(request),
        commit=True,
    )
    return SessionListResponse(
        count=len(records),
        sessions=[
            SessionInfo(
                jti=record.jti,
                created_at=record.created_at.isoformat() if record.created_at else None,
                expires_at=record.expires_at.isoformat() if record.expires_at else None,
                ip_address=record.ip_address,
                user_agent=record.user_agent,
                current=record.jti == current,
            )
            for record in records
        ],
    )
