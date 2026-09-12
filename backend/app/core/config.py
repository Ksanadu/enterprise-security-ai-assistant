"""Application configuration.

All runtime configuration is read from environment variables (optionally via a
``.env`` file). No secret is ever hardcoded: the only literal defaults here are
obviously-insecure *development* placeholders, and startup validation refuses to
run with them outside ``APP_ENV=development``.
"""

from __future__ import annotations

import json
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Repository root = .../backend/app/core/config.py -> parents[3]
BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent

# Deliberately obvious development placeholders. They are *not* secrets: startup
# validation rejects both of them whenever APP_ENV=production.
INSECURE_DEV_SECRET = "dev-only-insecure-change-me"  # noqa: S105
DEFAULT_DEMO_PASSWORD = "Demo@12345"  # noqa: S105

EnvName = Literal["development", "staging", "production", "test"]
LLMProvider = Literal["mock", "openai_compatible"]
EmbeddingProviderKind = Literal["tfidf", "openai_compatible"]
VectorStoreKind = Literal["faiss", "memory"]


def _split_csv(raw: str | list[str]) -> list[str]:
    """Normalise a comma-separated setting into a clean list."""
    if isinstance(raw, list):
        return [item.strip() for item in raw if str(item).strip()]
    return [item.strip() for item in str(raw).split(",") if item.strip()]


class Settings(BaseSettings):
    """Typed view over the process environment.

    Field names map to upper-case environment variables, e.g. ``app_env`` ->
    ``APP_ENV``. Unknown variables are ignored so the same ``.env`` can be shared
    with unrelated tooling.
    """

    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", BACKEND_DIR / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -- Application ------------------------------------------------------
    app_name: str = "Enterprise Security AI Assistant"
    app_env: EnvName = "development"
    debug: bool = True
    log_level: str = "INFO"
    log_format: Literal["text", "json"] = "text"

    # -- HTTP -------------------------------------------------------------
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    # ``NoDecode`` keeps pydantic-settings from JSON-decoding the raw value, so
    # the comma-separated form documented in .env.example is accepted
    # (e.g. "http://localhost:5173,http://127.0.0.1:5173") as well as a JSON list.
    api_cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    #: Number of reverse proxies in front of this process. ``0`` means the app is
    #: reachable directly and ``X-Forwarded-For`` is ignored entirely. Set it to
    #: the real hop count (the compose deployment uses 1, for nginx) or per-IP
    #: lockout and audit addresses degrade to the proxy's address.
    trusted_proxy_count: int = Field(default=0, ge=0, le=10)

    # -- Database ---------------------------------------------------------
    database_url: str = "sqlite:///./data/app.db"

    # -- Auth -------------------------------------------------------------
    auth_secret_key: str = INSECURE_DEV_SECRET
    auth_algorithm: str = "HS256"
    access_token_expire_minutes: int = 120
    allow_demo_login: bool = True
    #: bcrypt work factor. Lowered in tests so the suite stays fast.
    password_hash_rounds: int = 12
    #: Failed sign-ins allowed per account before a lockout.
    auth_max_login_attempts: int = 5
    #: Failed sign-ins allowed per source address before a lockout.
    auth_max_login_attempts_per_ip: int = 20
    #: Window over which failures are counted, and the lockout duration.
    auth_login_window_seconds: int = 900
    auth_lockout_seconds: int = 900
    #: How long revoked/expired session rows are kept as evidence.
    auth_session_retention_days: int = 30
    #: True when a random per-process signing key was generated (non-production
    #: only). Sessions do not survive a restart in that case.
    auth_secret_ephemeral: bool = False

    # -- Demo data (never enabled in production) --------------------------
    seed_demo_users: bool = True
    #: Password for the seeded demo accounts. Demo-only, never a real secret.
    demo_user_password: str = DEFAULT_DEMO_PASSWORD

    # -- LLM --------------------------------------------------------------
    llm_provider: LLMProvider = "mock"
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_temperature: float = 0.0
    llm_timeout_seconds: int = 45
    llm_max_retries: int = 2

    # -- Embeddings -------------------------------------------------------
    #: tfidf = offline lexical vector-space model, fitted on the knowledge base.
    #: openai_compatible = semantic embeddings from a hosted endpoint.
    embedding_provider: EmbeddingProviderKind = "tfidf"
    embedding_model: str = "text-embedding-3-small"
    #: Dimension for hosted embedding models. The offline "tfidf" provider
    #: derives its dimension from the fitted vocabulary instead.
    embedding_dim: int = 1536
    embedding_api_key: str = ""
    embedding_base_url: str = ""
    #: Safety valve on the fitted vocabulary size.
    embedding_max_features: int = 20000

    # -- Vector store -----------------------------------------------------
    vector_store: VectorStoreKind = "faiss"
    vector_store_path: str = "./data/vector_store"

    # -- Knowledge base / retrieval ---------------------------------------
    kb_dir: str = "./knowledge_base"
    #: Reject a malformed knowledge document instead of silently skipping it.
    #: A skipped document silently changes what the assistant may say, so this
    #: defaults to strict.
    kb_strict_validation: bool = True
    retrieval_top_k: int = 6
    #: Maximum chunks contributed by a single document, so one verbose document
    #: cannot crowd every other relevant document out of the context window.
    retrieval_max_per_document: int = 2
    #: Absolute floor on cosine similarity. Interpreted relative to the
    #: embedding provider's score distribution, so it is deliberately low: the
    #: relative floor below does most of the work.
    retrieval_min_score: float = 0.05
    #: Drop matches scoring below this fraction of the best match. A relative
    #: floor adapts to the provider (a lexical model and a semantic model have
    #: very different absolute score ranges) and keeps a weak tail of irrelevant
    #: chunks out of the prompt.
    #:
    #: Tuned against the evaluation set in ``tests/data/evaluation_questions.json``:
    #: 0.7 recalled the expected document for 86% of questions, 0.5 recalls 97%,
    #: and either way an irrelevant question still returns nothing. The floor is
    #: what keeps a weak tail out of the prompt, so it is set as high as the
    #: recall target allows rather than as low as possible.
    retrieval_relative_floor: float = 0.5
    retrieval_max_context_chars: int = 6000
    rag_chunk_max_chars: int = 700
    rag_chunk_overlap_chars: int = 100

    # -- Guardrails -------------------------------------------------------
    max_query_length: int = 2000
    chat_rate_limit_per_minute: int = 20
    #: Allow the language model to refine intent and to raise a risk level.
    #: Ignored when LLM_PROVIDER=mock: the offline generator cannot classify.
    #: The model may only ever *raise* a risk level, never lower one.
    classifier_use_llm: bool = True

    # -- Validators -------------------------------------------------------
    @field_validator("api_cors_origins", mode="before")
    @classmethod
    def _parse_cors(cls, value: object) -> object:
        """Accept both a JSON list and a comma-separated string."""
        if isinstance(value, str):
            raw = value.strip()
            if raw.startswith("["):
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"API_CORS_ORIGINS is not valid JSON: {exc}") from exc
                if not isinstance(parsed, list):
                    raise ValueError("API_CORS_ORIGINS JSON must be a list of origins")
                return [str(item).strip() for item in parsed if str(item).strip()]
            return _split_csv(raw)
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: object) -> object:
        return str(value).upper()

    @field_validator("llm_api_key", "embedding_api_key", mode="before")
    @classmethod
    def _strip_secret(cls, value: object) -> object:
        return str(value).strip() if value is not None else ""

    @model_validator(mode="after")
    def _validate_security_posture(self) -> Settings:
        """Fail fast on unsafe production configuration."""

        if self.app_env == "production":
            if self.auth_secret_key in {"", INSECURE_DEV_SECRET}:
                raise ValueError(
                    "AUTH_SECRET_KEY must be set to a strong random value when APP_ENV=production"
                )
            if len(self.auth_secret_key) < 32:
                raise ValueError("AUTH_SECRET_KEY must be at least 32 characters in production")
            if self.allow_demo_login:
                raise ValueError("ALLOW_DEMO_LOGIN must be false when APP_ENV=production")
            if self.seed_demo_users:
                raise ValueError("SEED_DEMO_USERS must be false when APP_ENV=production")
            if self.demo_user_password == DEFAULT_DEMO_PASSWORD:
                raise ValueError(
                    "DEMO_USER_PASSWORD must be changed from its default outside development"
                )
            if self.debug:
                raise ValueError("DEBUG must be false when APP_ENV=production")
            if "*" in self.api_cors_origins:
                raise ValueError("API_CORS_ORIGINS must not contain '*' in production")
            if self.llm_provider == "openai_compatible" and not self.llm_api_key:
                raise ValueError("LLM_API_KEY is required when LLM_PROVIDER=openai_compatible")

        if self.retrieval_top_k < 1:
            raise ValueError("RETRIEVAL_TOP_K must be >= 1")
        if self.retrieval_max_per_document < 1:
            raise ValueError("RETRIEVAL_MAX_PER_DOCUMENT must be >= 1")
        if not 0.0 <= self.retrieval_min_score <= 1.0:
            raise ValueError("RETRIEVAL_MIN_SCORE must be within [0, 1]")
        if not 0.0 <= self.retrieval_relative_floor <= 1.0:
            raise ValueError("RETRIEVAL_RELATIVE_FLOOR must be within [0, 1]")
        if self.max_query_length < 16:
            raise ValueError("MAX_QUERY_LENGTH must be >= 16")
        if self.chat_rate_limit_per_minute < 1:
            raise ValueError("CHAT_RATE_LIMIT_PER_MINUTE must be >= 1")
        if self.embedding_dim < 8:
            raise ValueError("EMBEDDING_DIM must be >= 8")
        if not 4 <= self.password_hash_rounds <= 16:
            raise ValueError("PASSWORD_HASH_ROUNDS must be between 4 and 16")
        if self.auth_max_login_attempts < 1:
            raise ValueError("AUTH_MAX_LOGIN_ATTEMPTS must be >= 1")
        if self.auth_max_login_attempts_per_ip < self.auth_max_login_attempts:
            raise ValueError("AUTH_MAX_LOGIN_ATTEMPTS_PER_IP must be >= AUTH_MAX_LOGIN_ATTEMPTS")
        if self.auth_lockout_seconds < 1:
            raise ValueError("AUTH_LOCKOUT_SECONDS must be >= 1")
        if self.rag_chunk_max_chars < 100:
            raise ValueError("RAG_CHUNK_MAX_CHARS must be >= 100")
        if not 0 <= self.rag_chunk_overlap_chars < self.rag_chunk_max_chars:
            raise ValueError("RAG_CHUNK_OVERLAP_CHARS must be >= 0 and < RAG_CHUNK_MAX_CHARS")
        if self.retrieval_max_context_chars < 500:
            raise ValueError("RETRIEVAL_MAX_CONTEXT_CHARS must be >= 500")

        # Outside production, never keep a *known* signing key. A placeholder
        # that is published in this repository would let anyone forge a token,
        # so a random per-process secret is generated instead. Sessions then end
        # when the process restarts; set AUTH_SECRET_KEY in .env for stability.
        if self.app_env != "production" and self.auth_secret_key in {"", INSECURE_DEV_SECRET}:
            self.auth_secret_key = secrets.token_urlsafe(48)
            self.auth_secret_ephemeral = True

        return self

    # -- Derived helpers --------------------------------------------------
    @property
    def is_development(self) -> bool:
        return self.app_env in {"development", "test"}

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def demo_login_enabled(self) -> bool:
        """Demo shortcuts are only ever active outside production."""
        return self.allow_demo_login and not self.is_production

    @property
    def sqlite_path(self) -> Path | None:
        """Absolute path of the SQLite file, or ``None`` for other backends."""
        prefix = "sqlite:///"
        if not self.database_url.startswith(prefix):
            return None
        raw = self.database_url[len(prefix) :]
        path = Path(raw)
        return path if path.is_absolute() else (BACKEND_DIR / path).resolve()

    @property
    def knowledge_base_dir(self) -> Path:
        path = Path(self.kb_dir)
        return path if path.is_absolute() else (BACKEND_DIR / path).resolve()

    @property
    def vector_store_dir(self) -> Path:
        path = Path(self.vector_store_path)
        return path if path.is_absolute() else (BACKEND_DIR / path).resolve()

    def ensure_directories(self) -> None:
        """Create runtime directories (SQLite parent, vector store, logs)."""
        db_path = self.sqlite_path
        if db_path is not None:
            db_path.parent.mkdir(parents=True, exist_ok=True)
        self.vector_store_dir.mkdir(parents=True, exist_ok=True)

    def public_summary(self) -> dict[str, object]:
        """Safe-to-expose configuration summary. Never contains secrets."""
        return {
            "app_env": self.app_env,
            "debug": self.debug,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "llm_configured": self.llm_provider == "mock" or bool(self.llm_api_key),
            "embedding_provider": self.embedding_provider,
            "embedding_dim": self.embedding_dim,
            "vector_store": self.vector_store,
            "retrieval_top_k": self.retrieval_top_k,
            "demo_login_enabled": self.demo_login_enabled,
            # Makes the effective client-address policy visible, since it decides
            # whether per-address lockout and audit addresses mean anything.
            "trusted_proxy_count": self.trusted_proxy_count,
            "demo_users_seeded": self.seed_demo_users,
            "auth_secret_ephemeral": self.auth_secret_ephemeral,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()


def generate_secret_key() -> str:
    """Helper used by docs/scripts to mint a strong ``AUTH_SECRET_KEY``."""
    return secrets.token_urlsafe(48)
