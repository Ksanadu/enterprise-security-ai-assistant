"""Request correlation and access logging middleware."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import request_id_var

logger = logging.getLogger("app.http")

REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a correlation id, time the request and log the outcome.

    The request body is never logged: it can contain user credentials and
    security-incident details.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Accept an upstream id only if it is short and safe to echo.
        incoming = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = (
            incoming
            if incoming and len(incoming) <= 64 and incoming.isascii() and incoming.isprintable()
            else uuid.uuid4().hex[:16]
        )
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "http_request_failed method=%s path=%s duration_ms=%.1f",
                request.method,
                request.url.path,
                duration_ms,
            )
            raise
        finally:
            request_id_var.reset(token)

        duration_ms = (time.perf_counter() - started) * 1000
        response.headers[REQUEST_ID_HEADER] = request_id
        # Security headers for any browser-facing deployment.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")

        # API responses carry policy text, incident answers and conversation
        # history. None of it belongs in a shared cache or the browser's history
        # cache.
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")

        if request.url.path not in {"/health", "/healthz"}:
            logger.info(
                "http_request method=%s path=%s status=%s duration_ms=%.1f",
                request.method,
                request.url.path,
                response.status_code,
                duration_ms,
            )
        return response
