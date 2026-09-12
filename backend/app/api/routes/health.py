"""Liveness/readiness and public metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlalchemy import text

from app import __version__
from app.api.deps import AppSettings, DbSession
from app.core.enums import Role
from app.schemas.common import HealthResponse, MetaResponse

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse, summary="Liveness and DB check")
def health(request: Request, session: DbSession, settings: AppSettings) -> HealthResponse:
    """Report process health plus a real database round-trip."""
    checks: dict[str, str] = {}
    try:
        session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:  # pragma: no cover - depends on external failure
        checks["database"] = "error"

    # The knowledge base is reported but does not make the process unhealthy:
    # authentication and health monitoring must keep working while an operator
    # fixes a malformed document.
    knowledge = getattr(request.app.state, "knowledge", None)
    if knowledge is None:
        checks["knowledge_base"] = "unavailable"
    elif knowledge.is_ready():
        checks["knowledge_base"] = "ok"
    else:
        checks["knowledge_base"] = "degraded"

    status = (
        "ok"
        if checks.get("database") == "ok" and checks.get("knowledge_base") != "unavailable"
        else "degraded"
    )
    return HealthResponse(
        status=status,
        app_name=settings.app_name,
        version=__version__,
        environment=settings.app_env,
        checks=checks,
    )


@router.get("/meta", response_model=MetaResponse, summary="Public configuration summary")
def meta(settings: AppSettings) -> MetaResponse:
    """Expose non-sensitive configuration so the UI can adapt.

    No secret, key or credential is ever included - see
    :meth:`app.core.config.Settings.public_summary`.
    """
    summary = settings.public_summary()
    return MetaResponse(
        app_name=settings.app_name,
        version=__version__,
        environment=settings.app_env,
        features={
            "demo_login": bool(summary["demo_login_enabled"]),
            "demo_users_seeded": bool(summary["demo_users_seeded"]),
        },
        ai={
            "llm_provider": summary["llm_provider"],
            "llm_model": summary["llm_model"],
            "llm_configured": summary["llm_configured"],
            "embedding_provider": summary["embedding_provider"],
            "vector_store": summary["vector_store"],
            "retrieval_top_k": summary["retrieval_top_k"],
        },
        roles=[role.value for role in Role],
    )
