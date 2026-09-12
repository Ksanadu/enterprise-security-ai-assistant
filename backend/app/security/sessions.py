"""Access-token session records: issuing, validating and revoking.

A signed token cannot be withdrawn before it expires. Recording every issued
token lets the application revoke one, all of a user's tokens, or the tokens of
a compromised account - and lets a user see where they are signed in.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any, cast

from sqlalchemy import CursorResult, delete, select, update
from sqlalchemy.orm import Session

from app.db.models import UserSession

logger = logging.getLogger(__name__)

#: Why a session record was revoked. Stored for the audit trail.
REASON_LOGOUT = "logout"
REASON_LOGOUT_ALL = "logout_all"
REASON_PASSWORD_CHANGED = "password_changed"  # noqa: S105 - a reason label, not a secret
REASON_ACCOUNT_DISABLED = "account_disabled"
REASON_ADMIN_REVOKED = "admin_revoked"
REASON_EXPIRED = "expired"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _as_aware(value: dt.datetime) -> dt.datetime:
    """SQLite returns naive datetimes; comparisons need a timezone."""
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)


def record_session(
    session: Session,
    *,
    user_id: int,
    jti: str,
    expires_at: dt.datetime,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> UserSession:
    """Persist a newly issued token."""
    record = UserSession(
        jti=jti,
        user_id=user_id,
        created_at=_now(),
        expires_at=_as_aware(expires_at),
        ip_address=ip_address,
        # Bounded: a client controls this header and it must not grow unbounded.
        user_agent=(user_agent or "")[:255] or None,
    )
    session.add(record)
    session.flush()
    return record


def get_active_session(session: Session, jti: str) -> UserSession | None:
    """Return the session for ``jti`` when it is neither revoked nor expired."""
    record = session.scalar(select(UserSession).where(UserSession.jti == jti))
    if record is None:
        return None
    if record.is_revoked:
        return None
    if _as_aware(record.expires_at) <= _now():
        return None
    return record


def revoke_session(
    session: Session,
    *,
    jti: str,
    reason: str = REASON_LOGOUT,
) -> bool:
    """Revoke one session. Returns ``True`` when a live session was revoked."""
    record = get_active_session(session, jti)
    if record is None:
        return False
    record.revoked_at = _now()
    record.revoked_reason = reason
    session.flush()
    logger.info("session_revoked user_id=%s reason=%s", record.user_id, reason)
    return True


def revoke_all_for_user(
    session: Session,
    *,
    user_id: int,
    reason: str = REASON_LOGOUT_ALL,
) -> int:
    """Revoke every live session for a user. Returns how many were revoked."""
    result = cast(
        CursorResult[Any],
        session.execute(
            update(UserSession)
            .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
            .values(revoked_at=_now(), revoked_reason=reason)
        ),
    )
    revoked = int(result.rowcount or 0)
    if revoked:
        logger.info("sessions_revoked_all user_id=%s count=%d reason=%s", user_id, revoked, reason)
    return revoked


def list_active_sessions(session: Session, *, user_id: int) -> list[UserSession]:
    """Live sessions for a user, newest first."""
    records = session.scalars(
        select(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.created_at.desc(), UserSession.id.desc())
    ).all()
    return [record for record in records if _as_aware(record.expires_at) > _now()]


def count_active_sessions(session: Session, *, user_id: int) -> int:
    return len(list_active_sessions(session, user_id=user_id))


def purge_expired_sessions(session: Session, *, retention_days: int = 30) -> int:
    """Delete session rows that expired more than ``retention_days`` ago.

    Revoked and expired rows are evidence, so they are kept for a while rather
    than removed immediately.
    """
    cutoff = _now() - dt.timedelta(days=max(1, retention_days))
    result = cast(
        CursorResult[Any],
        session.execute(delete(UserSession).where(UserSession.expires_at < cutoff)),
    )
    removed = int(result.rowcount or 0)
    if removed:
        logger.info("sessions_purged count=%d older_than_days=%d", removed, retention_days)
    return removed
