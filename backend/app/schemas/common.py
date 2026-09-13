"""Shared API schemas: health, metadata and the error envelope."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    """Uniform error envelope returned by every failing endpoint."""

    error: ErrorBody


class HealthResponse(BaseModel):
    status: str = Field(description="'ok' when every dependency check passes")
    app_name: str
    version: str
    environment: str
    checks: dict[str, str] = Field(default_factory=dict)


class MetaResponse(BaseModel):
    """What an *unauthenticated* caller may know about this deployment.

    Deliberately small. This endpoint needs no token, so everything here is public:
    the application name, its version, the environment and whether demo login is
    available (the sign-in screen has to know). The AI stack fingerprint that used
    to be here - provider, model, embedding backend, vector store and retrieval
    `top_k` - is gone. It told an anonymous caller exactly which surfaces to attack
    and how, and `environment: development` advertised that demo credentials were
    live. Operational detail now sits behind authentication, in
    `GET /api/v1/chat/capabilities`, and the rule counts inside it are visible only
    to the security role.
    """

    app_name: str
    version: str
    environment: str
    features: dict[str, bool] = Field(default_factory=dict)
    roles: list[str] = Field(default_factory=list)
