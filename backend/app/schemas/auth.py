"""Authentication schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.enums import Role


class LoginRequest(BaseModel):
    email: EmailStr
    #: Bounded to avoid unbounded password-hashing cost (DoS via huge input).
    password: str = Field(min_length=1, max_length=256)


class UserPublic(BaseModel):
    """User representation safe to return to the owner of the account."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str
    role: Role
    role_label: str = ""


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 scheme name, not a secret
    expires_in: int = Field(description="Token lifetime in seconds")
    user: UserPublic


class SessionInfo(BaseModel):
    """One active session. The jti is an opaque handle, not a credential."""

    jti: str
    created_at: str | None = None
    expires_at: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    current: bool = False


class SessionListResponse(BaseModel):
    count: int
    sessions: list[SessionInfo] = Field(default_factory=list)
