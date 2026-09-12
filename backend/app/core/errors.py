"""Domain error types and RFC7807-style exception handlers.

Every failure leaving the API has a stable machine-readable ``code``. Internal
details (stack traces, SQL, provider payloads) are logged but never returned to
the client outside debug mode.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings
from app.core.logging import redact, request_id_var

logger = logging.getLogger(__name__)


class AppError(Exception):
    """Base class for expected, client-safe application errors."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "app_error"
    message: str = "Request could not be processed."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.status_code = status_code or self.status_code
        self.details = details or {}
        super().__init__(self.message)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": {
                "code": self.code,
                "message": self.message,
                "request_id": request_id_var.get(),
            }
        }
        if self.details:
            payload["error"]["details"] = self.details
        return payload


class ConfigurationError(AppError):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    code = "configuration_error"
    message = "Server configuration is invalid."


class AuthenticationError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "authentication_required"
    message = "Authentication is required."


class PermissionDeniedError(AppError):
    """Raised when RBAC denies an action. The message stays deliberately vague."""

    status_code = status.HTTP_403_FORBIDDEN
    code = "permission_denied"
    message = "You do not have permission to access this resource."


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"
    message = "Resource not found."


class ValidationError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = "validation_error"
    message = "Request payload is invalid."


class RateLimitError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"
    message = "Too many requests. Please slow down."


class UpstreamServiceError(AppError):
    status_code = status.HTTP_502_BAD_GATEWAY
    code = "upstream_error"
    message = "An upstream service failed."


def register_exception_handlers(app: FastAPI) -> None:
    """Attach consistent JSON error responses to the application."""

    @app.exception_handler(AppError)
    async def _app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error("app_error code=%s message=%s", exc.code, exc.message)
        else:
            logger.info("app_error code=%s message=%s", exc.code, exc.message)
        return JSONResponse(status_code=exc.status_code, content=exc.to_payload())

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Keep field locations and messages, but echo no submitted values:
        # request bodies here can contain credentials.
        fields = [
            {
                "location": ".".join(str(part) for part in err.get("loc", ())),
                "message": str(err.get("msg", "invalid")),
                "type": str(err.get("type", "value_error")),
            }
            for err in exc.errors()
        ]
        logger.info("validation_error fields=%s", [f["location"] for f in fields])
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request payload is invalid.",
                    "request_id": request_id_var.get(),
                    "details": {"fields": fields},
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": f"http_{exc.status_code}",
                    "message": detail,
                    "request_id": request_id_var.get(),
                }
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_error path=%s", request.url.path)
        settings = get_settings()
        payload: dict[str, Any] = {
            "error": {
                "code": "internal_error",
                "message": "An internal error occurred.",
                "request_id": request_id_var.get(),
            }
        }
        if settings.debug:
            # Debug-only diagnostics; never enabled in production.
            payload["error"]["debug"] = redact(f"{type(exc).__name__}: {exc}")
        return JSONResponse(status_code=500, content=payload)
