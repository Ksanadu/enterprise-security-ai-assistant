"""FastAPI dependencies: settings, database session, the current principal and
the authorization gate.

Two decisions live here:

* **Identity comes from the session record, not from the token.** The token is
  only a pointer: the server-side record for its ``jti`` decides whether the
  session is still live, and which user it belongs to. That is what makes
  revocation possible.
* **Authorization is a dependency, never a client input.** There is no way for a
  request body to influence who the caller is or what they may do.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import AuditOutcome, Role
from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.security import decode_access_token
from app.db.models import User
from app.db.session import get_db
from app.security.audit import AuditAction, record_audit
from app.security.client_address import resolve_client_address
from app.security.sessions import get_active_session
from app.services.auth_service import get_user_by_id

# auto_error=False so we can return our own consistent 401 envelope.
bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def client_ip(request: Request) -> str | None:
    """Best-effort client address, proxied deployments included.

    ``X-Forwarded-For`` is honoured only as far as ``TRUSTED_PROXY_COUNT`` says
    this deployment may be behind proxies - and even then the address is read
    from the right-hand end of the header, where a client cannot write. With the
    default of ``0`` the header is ignored entirely and the socket peer is used,
    so a client that forges it changes nothing.

    See :mod:`app.security.client_address` for why this matters: behind a proxy
    the peer is the proxy, which would collapse per-address lockout into one
    shared bucket and record the proxy in every audit row.
    """
    return resolve_client_address(
        request.client.host if request.client else None,
        request.headers.get("X-Forwarded-For"),
        get_settings().trusted_proxy_count,
    )


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: DbSession,
) -> User:
    """Resolve the authenticated user from a bearer token and a live session."""
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Authentication is required.")

    claims = decode_access_token(credentials.credentials)

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        # Tokens always carry a jti; without one the session cannot be checked,
        # so fail closed rather than trusting the claim alone.
        raise AuthenticationError("Invalid credentials.")

    record = get_active_session(session, jti)
    if record is None:
        # Signed correctly but revoked, already used past expiry, or unknown.
        raise AuthenticationError("Your session has ended. Please sign in again.")

    # Cross-check the token against its own session record: they must agree.
    if str(record.user_id) != str(claims.get("sub", "")):
        raise AuthenticationError("Invalid credentials.")

    user = get_user_by_id(session, record.user_id)
    if user is None:
        raise AuthenticationError("Invalid credentials.")
    if not user.is_active:
        raise AuthenticationError("This account is disabled.")

    # `role` is read from the database, never from the token claim, so a stale
    # or tampered claim cannot escalate privileges.
    request.state.session_jti = jti
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def current_session_jti(request: Request) -> str | None:
    """The ``jti`` of the session that authenticated this request, if any."""
    return getattr(request.state, "session_jti", None)


def require_roles(*allowed: Role):
    """Dependency factory enforcing that the caller holds one of ``allowed``.

    Authorization is decided here, in backend code - never by the model and never
    by anything the client sends. A denial is audited, because "who tried to do
    what and was refused" is exactly the signal a security team needs.
    """

    allowed_set = {role.value for role in allowed}

    def _dependency(request: Request, user: CurrentUser, session: DbSession) -> User:
        if user.role.value not in allowed_set:
            record_audit(
                session,
                action=AuditAction.PERMISSION_DENIED,
                outcome=AuditOutcome.DENIED,
                actor=user,
                resource_type="endpoint",
                resource_id=f"{request.method} {request.url.path}",
                detail={"required_roles": sorted(allowed_set)},
                ip_address=client_ip(request),
                commit=True,
            )
            raise PermissionDeniedError()
        return user

    return _dependency


def get_db_session() -> Iterator[Session]:  # re-export for scripts/tests
    yield from get_db()
