"""Configuration and guardrail tests.

These tests encode the project's security posture: unsafe production settings
must fail loudly, and no secret may ever leak through a public surface.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import ValidationError

from app.core.config import (
    DEFAULT_DEMO_PASSWORD,
    INSECURE_DEV_SECRET,
    Settings,
    generate_secret_key,
)

#: The guardrails below are security controls: they are what stops an unsafe
#: configuration from starting at all, and what keeps a secret out of a payload
#: that anyone can read. Marked so ``pytest -m security`` includes them - a
#: security subset that omits the production guardrails is not a gate.
pytestmark = pytest.mark.security

SAFE_SECRET = "a" * 48


def _production(**overrides: object) -> Settings:
    """Build production settings with every safety switch satisfied."""
    base: dict[str, object] = {
        "app_env": "production",
        "debug": False,
        "allow_demo_login": False,
        "seed_demo_users": False,
        "auth_secret_key": SAFE_SECRET,
        "demo_user_password": "SomethingElse@9876",
        "api_cors_origins": ["https://assistant.example.com"],
    }
    base.update(overrides)
    # ``_env_file=None`` so the developer's local .env cannot influence the test.
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


class TestEnvironmentParsing:
    def test_defaults_are_development(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.app_env == "development"
        assert settings.is_development is True
        assert settings.is_production is False

    def test_cors_list_parsed_from_csv(self) -> None:
        settings = Settings(_env_file=None, api_cors_origins="http://a.test, http://b.test ,,")
        assert settings.api_cors_origins == ["http://a.test", "http://b.test"]

    def test_log_level_is_upper_cased(self) -> None:
        assert Settings(_env_file=None, log_level="debug").log_level == "DEBUG"

    def test_api_keys_are_trimmed(self) -> None:
        settings = Settings(_env_file=None, llm_api_key="  sk-abc  ")
        assert settings.llm_api_key == "sk-abc"

    def test_sqlite_path_is_absolute(self) -> None:
        settings = Settings(_env_file=None, database_url="sqlite:///./data/app.db")
        assert settings.sqlite_path is not None
        assert settings.sqlite_path.is_absolute()

    def test_non_sqlite_url_has_no_sqlite_path(self) -> None:
        settings = Settings(_env_file=None, database_url="postgresql://u@h/db")
        assert settings.sqlite_path is None


class TestProductionGuards:
    def test_valid_production_settings_are_accepted(self) -> None:
        settings = _production()
        assert settings.is_production is True
        assert settings.demo_login_enabled is False

    def test_default_secret_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError, match="AUTH_SECRET_KEY"):
            _production(auth_secret_key=INSECURE_DEV_SECRET)

    def test_short_secret_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError, match="at least 32 characters"):
            _production(auth_secret_key="too-short")

    def test_demo_login_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError, match="ALLOW_DEMO_LOGIN"):
            _production(allow_demo_login=True)

    def test_demo_seeding_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError, match="SEED_DEMO_USERS"):
            _production(seed_demo_users=True)

    def test_default_demo_password_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError, match="DEMO_USER_PASSWORD"):
            _production(demo_user_password=DEFAULT_DEMO_PASSWORD)

    def test_debug_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError, match="DEBUG"):
            _production(debug=True)

    def test_wildcard_cors_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError, match="API_CORS_ORIGINS"):
            _production(api_cors_origins=["*"])

    def test_missing_llm_key_rejected_for_openai_provider(self) -> None:
        with pytest.raises(ValidationError, match="LLM_API_KEY"):
            _production(llm_provider="openai_compatible", llm_api_key="")

    def test_mock_provider_needs_no_key_in_production(self) -> None:
        settings = _production(llm_provider="mock", llm_api_key="")
        assert settings.llm_provider == "mock"


class TestDotEnvLoading:
    """Regression guard: values written the way .env.example documents them must
    load correctly. pydantic-settings JSON-decodes complex fields by default,
    which silently broke the comma-separated CORS list."""

    def test_csv_cors_origins_load_from_env_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "API_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173\n",
            encoding="utf-8",
        )
        settings = Settings(_env_file=env_file)  # type: ignore[arg-type]
        assert settings.api_cors_origins == [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]

    def test_json_cors_origins_still_load(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            'API_CORS_ORIGINS=["https://a.test", "https://b.test"]\n', encoding="utf-8"
        )
        settings = Settings(_env_file=env_file)  # type: ignore[arg-type]
        assert settings.api_cors_origins == ["https://a.test", "https://b.test"]

    def test_malformed_json_cors_is_rejected(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text('API_CORS_ORIGINS=["unterminated"\n', encoding="utf-8")
        with pytest.raises(ValidationError):
            Settings(_env_file=env_file)  # type: ignore[arg-type]

    def test_scalar_values_load_from_env_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "\n".join(
                [
                    "APP_ENV=staging",
                    "RETRIEVAL_TOP_K=7",
                    "RETRIEVAL_MIN_SCORE=0.42",
                    "DEBUG=false",
                    "AUTH_SECRET_KEY=stable-development-key-for-the-env-file-test",
                ]
            ),
            encoding="utf-8",
        )
        settings = Settings(_env_file=env_file)  # type: ignore[arg-type]
        assert settings.app_env == "staging"
        assert settings.retrieval_top_k == 7
        assert settings.retrieval_min_score == pytest.approx(0.42)
        assert settings.debug is False
        assert settings.auth_secret_ephemeral is False

    def test_shipped_env_example_is_valid(self) -> None:
        """The template that ships with the repo must load without errors."""
        example = Path(__file__).resolve().parents[2] / ".env.example"
        assert example.is_file(), "the repository must ship a .env.example template"

        settings = Settings(_env_file=example)  # type: ignore[arg-type]
        assert settings.app_env == "development"
        assert settings.api_cors_origins
        assert settings.llm_provider in {"mock", "openai_compatible"}

    def test_env_example_contains_no_real_credentials(self) -> None:
        example = Path(__file__).resolve().parents[2] / ".env.example"
        text = example.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            if key.strip() in {"LLM_API_KEY", "EMBEDDING_API_KEY"}:
                assert value.strip() == "", f"{key} must ship empty in .env.example"


class TestTheShippedDefaultsAreTheTestedDefaults:
    """The drift that made every quality number describe a system nobody ran.

    `RETRIEVAL_RELATIVE_FLOOR` was 0.5 in the tests and 0.7 in the shipped `.env`,
    so expected-document recall measured 28/28 in the suite and 25/28 against the
    running product - and the README reported the suite's number as the product's.
    These assertions make the three places a default is written - the code, the
    template a fresh clone copies, and the README a human reads - fail loudly when
    they disagree. They are deliberately strict about *values*, because a default
    is a claim about behaviour.
    """

    #: The retrieval and provider defaults the documentation publishes.
    PUBLISHED: ClassVar[dict[str, str]] = {
        "LLM_PROVIDER": "mock",
        "EMBEDDING_PROVIDER": "tfidf",
        "VECTOR_STORE": "faiss",
        "RETRIEVAL_TOP_K": "6",
        "RETRIEVAL_MIN_SCORE": "0.05",
        "RETRIEVAL_RELATIVE_FLOOR": "0.5",
    }

    @staticmethod
    def _env_example() -> dict[str, str]:
        example = Path(__file__).resolve().parents[2] / ".env.example"
        values: dict[str, str] = {}
        for line in example.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            values[key.strip()] = value.strip()
        return values

    @staticmethod
    def _readme_table() -> dict[str, str]:
        readme = Path(__file__).resolve().parents[2] / "README.md"
        documented: dict[str, str] = {}
        for line in readme.read_text(encoding="utf-8").splitlines():
            if not line.startswith("| `"):
                continue
            cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0] in TestTheShippedDefaultsAreTheTestedDefaults.PUBLISHED:
                documented[cells[0]] = cells[1]
        return documented

    def test_the_code_defaults_are_the_published_defaults(self) -> None:
        fields = Settings.model_fields
        for name, expected in self.PUBLISHED.items():
            default = fields[name.lower()].default
            assert str(default).lower() == expected.lower(), (
                f"{name}: the code default is {default!r}, the documentation says {expected!r}"
            )

    def test_env_example_matches_the_code_defaults(self) -> None:
        # A fresh clone copies this file, so a different value here is a different
        # product from the one the test suite measures.
        values = self._env_example()
        for name, expected in self.PUBLISHED.items():
            assert name in values, f"{name} is missing from .env.example"
            assert values[name].lower() == expected.lower(), (
                f"{name}: .env.example says {values[name]!r}, the code default is {expected!r}"
            )

    def test_the_readme_documents_the_same_defaults(self) -> None:
        documented = self._readme_table()
        for name, expected in self.PUBLISHED.items():
            assert name in documented, f"{name} is not documented in the README settings table"
            assert documented[name].lower() == expected.lower(), (
                f"{name}: the README says {documented[name]!r}, the code default is {expected!r}"
            )


class TestSigningKey:
    def test_placeholder_key_is_replaced_outside_production(self) -> None:
        settings = Settings(_env_file=None, auth_secret_key=INSECURE_DEV_SECRET)
        assert settings.auth_secret_key != INSECURE_DEV_SECRET
        assert len(settings.auth_secret_key) >= 32
        assert settings.auth_secret_ephemeral is True

    def test_absent_key_is_replaced_outside_production(self) -> None:
        settings = Settings(_env_file=None, auth_secret_key="")
        assert settings.auth_secret_key
        assert settings.auth_secret_ephemeral is True

    def test_two_processes_do_not_share_a_key(self) -> None:
        first = Settings(_env_file=None, auth_secret_key=INSECURE_DEV_SECRET)
        second = Settings(_env_file=None, auth_secret_key=INSECURE_DEV_SECRET)
        assert first.auth_secret_key != second.auth_secret_key

    def test_explicit_key_is_kept(self) -> None:
        settings = Settings(_env_file=None, auth_secret_key="explicit-development-key-value")
        assert settings.auth_secret_key == "explicit-development-key-value"
        assert settings.auth_secret_ephemeral is False

    def test_ephemeral_flag_is_visible_but_key_is_not(self) -> None:
        settings = Settings(_env_file=None, auth_secret_key=INSECURE_DEV_SECRET)
        summary = settings.public_summary()
        assert summary["auth_secret_ephemeral"] is True
        assert settings.auth_secret_key not in repr(summary)


class TestNumericBounds:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("retrieval_top_k", 0),
            ("retrieval_min_score", 1.5),
            ("retrieval_min_score", -0.1),
            ("max_query_length", 5),
            ("embedding_dim", 4),
            ("password_hash_rounds", 2),
            ("password_hash_rounds", 20),
        ],
    )
    def test_out_of_range_values_rejected(self, field: str, value: object) -> None:
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{field: value})  # type: ignore[arg-type]


class TestSecretExposure:
    def test_public_summary_contains_no_secret_material(self) -> None:
        settings = Settings(
            _env_file=None,
            llm_provider="openai_compatible",
            llm_api_key="sk-super-secret-value",
            embedding_api_key="sk-embedding-secret",
            auth_secret_key=SAFE_SECRET,
            demo_user_password="Demo@12345",
        )
        serialised = repr(settings.public_summary())
        for secret in (
            "sk-super-secret-value",
            "sk-embedding-secret",
            SAFE_SECRET,
            "Demo@12345",
        ):
            assert secret not in serialised

    def test_public_summary_reports_provider_without_key(self) -> None:
        summary = Settings(
            _env_file=None, llm_provider="openai_compatible", llm_api_key="sk-x"
        ).public_summary()
        assert summary["llm_configured"] is True
        assert "llm_api_key" not in summary

    def test_generate_secret_key_is_strong(self) -> None:
        key = generate_secret_key()
        assert len(key) >= 48
        assert key != generate_secret_key()
