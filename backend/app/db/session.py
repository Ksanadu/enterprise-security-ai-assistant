"""Engine and session management.

A single SQLAlchemy engine is created lazily per settings object so tests can
point ``DATABASE_URL`` at a temporary file and clear the cache.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.db.base import Base

logger = logging.getLogger(__name__)

#: Engines created in this process, so shutdown/tests can dispose them all.
_ENGINES: list[Engine] = []


def _engine_kwargs(settings: Settings) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"future": True, "pool_pre_ping": True}
    if settings.database_url.startswith("sqlite"):
        # FastAPI serves requests from a thread pool; SQLite needs this flag.
        kwargs["connect_args"] = {"check_same_thread": False}
    return kwargs


@lru_cache(maxsize=4)
def _build_engine(database_url: str) -> Engine:
    settings = get_settings()
    engine = create_engine(database_url, **_engine_kwargs(settings))

    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            # Referential integrity is off by default in SQLite.
            cursor.execute("PRAGMA foreign_keys=ON")
            # WAL keeps concurrent readers working while a write is in flight.
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    _ENGINES.append(engine)
    return engine


def get_engine(settings: Settings | None = None) -> Engine:
    """Return the process-wide engine for the configured database URL."""
    settings = settings or get_settings()
    return _build_engine(settings.database_url)


@lru_cache(maxsize=4)
def _build_session_factory(database_url: str) -> sessionmaker[Session]:
    return sessionmaker(bind=_build_engine(database_url), autoflush=False, expire_on_commit=False)


def get_session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    settings = settings or get_settings()
    return _build_session_factory(settings.database_url)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for scripts and background tasks."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def _missing_columns(engine: Engine, settings: Settings) -> dict[str, list[str]]:
    """Tables that exist but lack columns the models now declare.

    This project has no migration tool, and ``create_all`` only creates missing
    *tables* - it never alters an existing one. Without this check, adding a
    column produces a confusing "no such column" error at the first query
    instead of a clear message at startup.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    drift: dict[str, list[str]] = {}

    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            continue
        present = {column["name"] for column in inspector.get_columns(table_name)}
        missing = sorted({column.name for column in table.columns} - present)
        if missing:
            drift[table_name] = missing

    del settings
    return drift


def _resolve_schema_drift(engine: Engine, settings: Settings) -> None:
    """Drop and recreate drifted tables in development, refuse elsewhere.

    Demo data is disposable and is re-seeded on startup, so in development the
    pragmatic answer is to rebuild. Outside development the data is not
    disposable, so refuse to start and tell the operator what to migrate.
    """
    drift = _missing_columns(engine, settings)
    if not drift:
        return

    summary = "; ".join(f"{table}: {', '.join(columns)}" for table, columns in drift.items())
    if not settings.is_development:
        raise RuntimeError(
            "Database schema is out of date and this build has no migrations. "
            f"Missing columns -> {summary}. Migrate the database before starting."
        )

    logger.warning("schema_drift_detected rebuilding_tables=%s", summary)
    Base.metadata.drop_all(bind=engine, tables=[Base.metadata.tables[name] for name in drift])


def init_db(settings: Settings | None = None) -> None:
    """Create runtime directories and all tables (idempotent)."""
    settings = settings or get_settings()
    settings.ensure_directories()
    # Import models so every table is registered on Base.metadata.
    from app.db import models  # noqa: F401  (side-effect import)

    engine = get_engine(settings)
    _resolve_schema_drift(engine, settings)
    Base.metadata.create_all(bind=engine)
    logger.info("database_initialised url=%s", _safe_url(settings.database_url))


def reset_engine_cache() -> None:
    """Dispose and drop cached engines/factories (tests after changing settings)."""
    dispose_engine()
    _build_engine.cache_clear()
    _build_session_factory.cache_clear()


def dispose_engine() -> None:
    """Close pooled connections for every engine created in this process."""
    while _ENGINES:
        engine = _ENGINES.pop()
        try:
            engine.dispose()
        except Exception:  # pragma: no cover - shutdown best effort
            logger.debug("engine dispose skipped", exc_info=True)


def _safe_url(url: str) -> str:
    """Strip credentials from a database URL before logging it."""
    if "@" in url and "//" in url:
        scheme, _, rest = url.partition("//")
        _, _, host = rest.rpartition("@")
        return f"{scheme}//***@{host}"
    return url
