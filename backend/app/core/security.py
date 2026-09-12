"""Password hashing and signed access tokens.

Passwords are hashed with bcrypt. Tokens are short-lived HMAC-signed JWTs whose
claims carry only the user id and role - never document permissions, never the
raw password, never any secret material.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hmac
import secrets
from typing import Any

import bcrypt
import jwt

from app.core.config import Settings, get_settings
from app.core.errors import AuthenticationError

# bcrypt only consumes the first 72 bytes of input.
BCRYPT_MAX_BYTES = 72
MIN_PASSWORD_LENGTH = 8


def _password_bytes(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if len(encoded) > BCRYPT_MAX_BYTES:
        # Truncate explicitly rather than letting bcrypt silently ignore the tail.
        return encoded[:BCRYPT_MAX_BYTES]
    return encoded


def hash_password(password: str, rounds: int | None = None) -> str:
    """Return a bcrypt hash for ``password``.

    ``rounds`` defaults to ``PASSWORD_HASH_ROUNDS`` (12 in production).
    """
    if not password:
        raise ValueError("password must not be empty")
    if rounds is None:
        try:
            rounds = get_settings().password_hash_rounds
        except Exception:  # pragma: no cover - settings must be loadable
            rounds = 12
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verification of ``password`` against ``password_hash``."""
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(_password_bytes(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Malformed hash in storage must not crash the request path.
        return False


def validate_password_strength(password: str) -> list[str]:
    """Return a list of policy violations (empty when the password is fine)."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters long")
    if not any(ch.isalpha() for ch in password):
        problems.append("must contain a letter")
    if not any(ch.isdigit() for ch in password):
        problems.append("must contain a digit")
    return problems


@dataclasses.dataclass(frozen=True, slots=True)
class AccessToken:
    """An issued token plus the claims needed to record and revoke it."""

    token: str
    jti: str
    subject: str
    role: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    claims: dict[str, Any]

    @property
    def expires_in(self) -> int:
        """Lifetime in seconds, for the OAuth2-style response."""
        return max(0, int((self.expires_at - self.issued_at).total_seconds()))


def create_access_token(
    *,
    subject: str,
    role: str,
    settings: Settings | None = None,
    expires_minutes: int | None = None,
) -> AccessToken:
    """Create a signed access token.

    The returned object carries the ``jti`` and expiry so the caller can record a
    server-side session and make the token revocable.
    """
    settings = settings or get_settings()
    lifetime = dt.timedelta(minutes=expires_minutes or settings.access_token_expire_minutes)
    now = dt.datetime.now(dt.UTC)
    expires_at = now + lifetime
    claims: dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": secrets.token_urlsafe(16),
        "iss": "esaa",
    }
    token = jwt.encode(claims, settings.auth_secret_key, algorithm=settings.auth_algorithm)
    return AccessToken(
        token=token,
        jti=str(claims["jti"]),
        subject=str(subject),
        role=role,
        issued_at=now,
        expires_at=expires_at,
        claims=claims,
    )


def decode_access_token(token: str, settings: Settings | None = None) -> dict[str, Any]:
    """Decode and verify a token, raising :class:`AuthenticationError` on failure."""
    settings = settings or get_settings()
    try:
        claims = jwt.decode(
            token,
            settings.auth_secret_key,
            algorithms=[settings.auth_algorithm],
            issuer="esaa",
            options={"require": ["exp", "sub", "role"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Session expired. Please sign in again.") from exc
    except jwt.InvalidTokenError as exc:
        # Deliberately generic: never leak which check failed.
        raise AuthenticationError("Invalid credentials.") from exc
    return claims


def constant_time_equals(left: str, right: str) -> bool:
    """Timing-safe string comparison for non-password secrets."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
