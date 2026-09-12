"""Authentication service.

Design notes
------------
* Credentials are verified against a bcrypt hash; the plaintext password is
  never logged, stored or echoed back.
* Unknown-account and wrong-password failures produce the *same* error and take
  a similar amount of time (a dummy hash comparison runs for unknown accounts),
  so the endpoint cannot be used to enumerate valid email addresses.
* Every attempt is audited, including failures.
"""

from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import AuditOutcome
from app.core.errors import AuthenticationError
from app.core.security import verify_password
from app.db.models import User
from app.security.audit import AuditAction, record_audit

logger = logging.getLogger(__name__)

#: Verified against when the account does not exist, to equalise timing.
_DUMMY_HASH = "$2b$12$" + "x" * 53


def _find_user(session: Session, email: str) -> User | None:
    return session.scalar(select(User).where(User.email == email.strip().lower()))


def authenticate(
    session: Session,
    *,
    email: str,
    password: str,
    ip_address: str | None = None,
) -> User:
    """Verify credentials and return the user.

    Raises :class:`AuthenticationError` for every failure mode with an identical
    message so callers cannot distinguish "no such user" from "bad password".
    """
    generic = "Invalid email or password."
    user = _find_user(session, email)

    if user is None:
        verify_password(password, _DUMMY_HASH)  # timing equalisation
        record_audit(
            session,
            action=AuditAction.LOGIN_FAILURE,
            outcome=AuditOutcome.DENIED,
            resource_type="user",
            detail={"reason": "unknown_account"},
            ip_address=ip_address,
            commit=True,
        )
        logger.info("login_failed reason=unknown_account")
        raise AuthenticationError(generic)

    if not verify_password(password, user.password_hash):
        record_audit(
            session,
            action=AuditAction.LOGIN_FAILURE,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="user",
            resource_id=user.id,
            detail={"reason": "bad_password"},
            ip_address=ip_address,
            commit=True,
        )
        logger.info("login_failed reason=bad_password user_id=%s", user.id)
        raise AuthenticationError(generic)

    if not user.is_active:
        record_audit(
            session,
            action=AuditAction.LOGIN_DENIED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="user",
            resource_id=user.id,
            detail={"reason": "inactive_account"},
            ip_address=ip_address,
            commit=True,
        )
        logger.info("login_denied reason=inactive_account user_id=%s", user.id)
        raise AuthenticationError("This account is disabled.")

    user.last_login_at = dt.datetime.now(dt.UTC)
    record_audit(
        session,
        action=AuditAction.LOGIN_SUCCESS,
        actor=user,
        resource_type="user",
        resource_id=user.id,
        detail={"role": user.role.value},
        ip_address=ip_address,
        commit=True,
    )
    logger.info("login_success user_id=%s role=%s", user.id, user.role.value)
    return user


def get_user_by_id(session: Session, user_id: int) -> User | None:
    return session.get(User, user_id)
