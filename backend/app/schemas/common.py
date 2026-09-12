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
    """Public, non-sensitive view of the running configuration."""

    app_name: str
    version: str
    environment: str
    features: dict[str, bool] = Field(default_factory=dict)
    ai: dict[str, Any] = Field(default_factory=dict)
    roles: list[str] = Field(default_factory=list)
