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


@router.get("/meta", response_model=MetaResponse, summary="Public application metadata")
def meta(settings: AppSettings) -> MetaResponse:
    """The minimum an unauthenticated client needs to render the app.

    Name, version, environment and the feature flags the sign-in screen depends on.
    Nothing about the AI stack: an anonymous caller used to learn the provider, the
    model, the embedding backend, the vector store, the retrieval `top_k` and that
    demo users were seeded, which is a target list rather than a feature list.
    """
    return MetaResponse(
        app_name=settings.app_name,
        version=__version__,
        environment=settings.app_env,
        features={
            "demo_login": settings.demo_login_enabled,
            "demo_users_seeded": settings.seed_demo_users,
        },
        roles=[role.value for role in Role],
    )
