"""Aggregate API router.

Versioned under ``/api/v1``. Every new feature registers exactly one router here
so the public surface stays easy to audit.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import auth, chat, dashboard, health, knowledge, tickets

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(knowledge.router)
api_router.include_router(chat.router)
api_router.include_router(tickets.router)
api_router.include_router(dashboard.router)

__all__ = ["api_router"]
