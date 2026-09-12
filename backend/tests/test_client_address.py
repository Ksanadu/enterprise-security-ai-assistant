"""Tests for client-address resolution behind a reverse proxy.

The deployment puts nginx in front of the API, which turns
``request.client.host`` into the proxy's address for every request. These tests
pin down the fix, and - more importantly - pin down that a client cannot forge
its own address by sending ``X-Forwarded-For``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.db.models import AuditLog
from app.db.session import get_session_factory, reset_engine_cache
from app.main import create_app
from app.security.audit import AuditAction
from app.security.client_address import resolve_client_address
from app.security.login_guard import LoginGuard

pytestmark = pytest.mark.security

PROXY = "172.18.0.5"
CLIENT = "203.0.113.7"


class TestDirectDeployment:
    """trusted_proxy_count = 0: the header must be inert."""

    def test_returns_the_socket_peer(self) -> None:
        assert resolve_client_address(CLIENT, None, 0) == CLIENT

    @pytest.mark.parametrize(
        "forged",
        [
            "10.0.0.1",
            "1.2.3.4, 5.6.7.8",
            "not-an-ip",
            "",
            "   ",
            "10.0.0.1:443",
        ],
    )
    def test_a_forged_header_cannot_change_the_address(self, forged: str) -> None:
        assert resolve_client_address(CLIENT, forged, 0) == CLIENT

    def test_no_peer_and_no_header_yields_nothing(self) -> None:
        assert resolve_client_address(None, None, 0) is None

    def test_a_negative_count_is_treated_as_direct(self) -> None:
        # Defensive: the setting is validated, but the function must not trust
        # its caller either.
        assert resolve_client_address(CLIENT, "10.0.0.1", -1) == CLIENT


class TestSingleTrustedProxy:
    """trusted_proxy_count = 1: the client is the last entry of the header."""

    def test_nginx_style_header_is_read(self) -> None:
        # nginx set the header and the client sent nothing of its own.
        assert resolve_client_address(PROXY, CLIENT, 1) == CLIENT

    def test_the_address_is_read_from_the_right(self) -> None:
        # The client prepended a value. nginx appended the real address, so the
        # rightmost entry is the genuine one and the forgery is never read.
        header = f"10.0.0.1, {CLIENT}"
        assert resolve_client_address(PROXY, header, 1) == CLIENT

    def test_a_long_forged_prefix_is_still_ignored(self) -> None:
        forged = ", ".join(f"10.0.0.{n}" for n in range(1, 60))
        assert resolve_client_address(PROXY, f"{forged}, {CLIENT}", 1) == CLIENT

    def test_an_absent_header_falls_back_to_the_peer(self) -> None:
        # A proxy that does not set the header must not produce a None address.
        assert resolve_client_address(PROXY, None, 1) == PROXY

    def test_a_header_with_no_valid_entry_falls_back_to_the_peer(self) -> None:
        assert resolve_client_address(PROXY, "unknown, obfuscated", 1) == PROXY

    def test_non_ip_entries_are_skipped(self) -> None:
        # "unknown" is emitted by some proxies; the real address is still found.
        assert resolve_client_address(PROXY, f"unknown, {CLIENT}", 1) == CLIENT


class TestChainedProxies:
    def test_two_proxies_read_the_second_entry_from_the_right(self) -> None:
        # client -> proxy1 -> proxy2 -> app
        header = f"{CLIENT}, 172.18.0.9"
        assert resolve_client_address("172.18.0.10", header, 2) == CLIENT

    def test_a_forged_prefix_is_ignored_with_two_proxies(self) -> None:
        header = f"10.0.0.1, {CLIENT}, 172.18.0.9"
        assert resolve_client_address("172.18.0.10", header, 2) == CLIENT

    def test_too_few_entries_falls_back_to_the_leftmost_available(self) -> None:
        # A misconfiguration, and the honest behaviour: use what is there rather
        # than inventing an address. Documented in the setting's description.
        assert resolve_client_address(PROXY, CLIENT, 3) == CLIENT


class TestNormalisation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("203.0.113.7", "203.0.113.7"),
            ("  203.0.113.7  ", "203.0.113.7"),
            ("203.0.113.7:41234", "203.0.113.7"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
            # IPv4-mapped IPv6 normalises to its IPv4 form, so one client cannot
            # occupy two lockout buckets by appearing under both spellings.
            ("::ffff:203.0.113.7", "203.0.113.7"),
            ("::FFFF:203.0.113.7", "203.0.113.7"),
        ],
    )
    def test_real_addresses_are_accepted_and_normalised(self, raw: str, expected: str) -> None:
        assert resolve_client_address(raw, None, 0) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "localhost",
            "example.com",
            "203.0.113.7; DROP TABLE users",
            "999.999.999.999",
            "<script>alert(1)</script>",
            "a" * 300,
        ],
    )
    def test_nothing_but_an_ip_literal_is_accepted_from_the_header(self, raw: str) -> None:
        # The header is the one client-controlled input here, so nothing that is
        # not an IP address can reach an audit row through it: no injected text,
        # no hostname, no unbounded string.
        assert resolve_client_address(PROXY, raw, 1) == PROXY

    @pytest.mark.parametrize("raw", ["localhost", "testclient", "unix:/run/app.sock"])
    def test_a_non_ip_socket_peer_is_recorded_verbatim(self, raw: str) -> None:
        # The peer address is written by the operating system, not the client, so
        # it is not attacker-controlled and must not be discarded: dropping it
        # would lose the only address the process actually observed.
        assert resolve_client_address(raw, None, 0) == raw

    def test_an_unbounded_peer_is_truncated(self) -> None:
        assert len(resolve_client_address("x" * 500, None, 0) or "") == 64


class TestClientAddressIsUsedByTheApplication:
    """The unit above only matters if the request path actually calls it."""

    @pytest.fixture
    def proxied_client(
        self, _settings_env: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> Iterator[TestClient]:
        for key, value in _settings_env.items():
            monkeypatch.setenv(key, value)
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'proxied.db').as_posix()}")
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")

        get_settings.cache_clear()
        reset_engine_cache()
        application = create_app(get_settings())
        try:
            with TestClient(application, raise_server_exceptions=False) as test_client:
                yield test_client
        finally:
            reset_engine_cache()
            get_settings.cache_clear()

    def test_the_real_client_address_reaches_the_audit_trail(
        self, proxied_client: TestClient
    ) -> None:
        # The socket peer is the test client, but the audit record must show the
        # address nginx reported, not the proxy.
        response = proxied_client.post(
            "/api/v1/auth/login",
            json={"email": "employee@example.com", "password": "Demo@12345"},
            headers={"X-Forwarded-For": CLIENT},
        )
        assert response.status_code == 200, response.text

        with get_session_factory()() as session:
            rows = (
                session.query(AuditLog)
                .filter(AuditLog.action == AuditAction.LOGIN_SUCCESS)
                .all()
            )
            assert rows, "the login was not audited"
            assert rows[-1].ip_address == CLIENT

    def test_a_forged_header_does_not_override_the_proxy_address(
        self, proxied_client: TestClient
    ) -> None:
        # With one trusted proxy the *last* entry wins, so a client that prepends
        # its own address cannot make the audit trail lie.
        response = proxied_client.post(
            "/api/v1/auth/login",
            json={"email": "employee@example.com", "password": "Demo@12345"},
            headers={"X-Forwarded-For": f"10.0.0.1, {CLIENT}"},
        )
        assert response.status_code == 200, response.text

        with get_session_factory()() as session:
            rows = (
                session.query(AuditLog)
                .filter(AuditLog.action == AuditAction.LOGIN_SUCCESS)
                .all()
            )
            assert rows[-1].ip_address == CLIENT


class TestPerAddressLockoutBehindAProxy:
    """The reason the address has to be right: sign-in lockout is keyed on it."""

    @pytest.fixture
    def proxied_app(
        self, _settings_env: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> Iterator[Any]:
        for key, value in _settings_env.items():
            monkeypatch.setenv(key, value)
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'lockout.db').as_posix()}")
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")

        get_settings.cache_clear()
        reset_engine_cache()
        application = create_app(get_settings())
        try:
            yield application
        finally:
            reset_engine_cache()
            get_settings.cache_clear()

    @pytest.fixture
    def proxied_client(self, proxied_app: Any) -> Iterator[TestClient]:
        with TestClient(proxied_app, raise_server_exceptions=False) as test_client:
            yield test_client

    @staticmethod
    def _fail_login(client: TestClient, forwarded_for: str, email: str = "nobody@example.com") -> int:
        return client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong"},
            headers={"X-Forwarded-For": forwarded_for},
        ).status_code

    def _exhaust_address_budget(self, client: TestClient, forwarded_for: str) -> None:
        """Trip the per-address limit without tripping any per-account limit.

        The address limit is floored at the account limit (a single account's
        retries must not be able to lock out everyone behind one NAT), so with
        ``max_attempts=2`` and ``ip_max_attempts=3`` the only way to reach the
        address ceiling is to fail *different* accounts from the same address.
        """
        for index in range(3):
            assert self._fail_login(client, forwarded_for, f"nobody{index}@example.com") == 401

    def test_the_per_address_limit_triggers_over_http(
        self, proxied_client: TestClient, proxied_app: Any
    ) -> None:
        proxied_app.state.login_guard = LoginGuard(max_attempts=2, ip_max_attempts=3)

        self._exhaust_address_budget(proxied_client, CLIENT)

        assert self._fail_login(proxied_client, CLIENT, "someone-else@example.com") == 429

    def test_a_different_client_address_gets_its_own_budget(
        self, proxied_client: TestClient, proxied_app: Any
    ) -> None:
        # Exactly what breaks if every request is attributed to the proxy: one
        # attacker exhausts the shared bucket and locks everybody out.
        proxied_app.state.login_guard = LoginGuard(max_attempts=2, ip_max_attempts=3)

        self._exhaust_address_budget(proxied_client, CLIENT)
        assert self._fail_login(proxied_client, CLIENT, "someone-else@example.com") == 429

        # An unrelated address is unaffected by the exhausted bucket.
        assert self._fail_login(proxied_client, "198.51.100.23") == 401

    def test_a_forged_address_cannot_evade_the_lockout(
        self, proxied_client: TestClient, proxied_app: Any
    ) -> None:
        # The attacker varies the *left* of the header, which is never read, so
        # the bucket they are counted in does not change.
        proxied_app.state.login_guard = LoginGuard(max_attempts=2, ip_max_attempts=3)

        for index in range(3):
            self._fail_login(proxied_client, f"10.0.0.{index}, {CLIENT}", f"nobody{index}@example.com")

        assert self._fail_login(proxied_client, f"10.0.0.99, {CLIENT}", "x@example.com") == 429

    def test_the_address_limit_can_never_be_lower_than_the_account_limit(self) -> None:
        # A deliberate property, not an accident: if the address budget were
        # smaller, a handful of mistypes by one user behind a shared NAT address
        # would lock out every other user at that address.
        guard = LoginGuard(max_attempts=5, ip_max_attempts=1)
        for _ in range(4):
            guard.record_failure(email="someone@example.com", ip_address=CLIENT)
        # Four failures is below the account limit of 5, and must also be below
        # the address limit even though ip_max_attempts said 1.
        assert guard.is_locked(email="someone@example.com", ip_address=CLIENT) is False


class TestConfigurationGuardrails:
    def test_the_default_is_the_safe_value(self) -> None:
        # A deployment that says nothing gets the non-spoofable behaviour.
        assert Settings(_env_file=None).trusted_proxy_count == 0  # type: ignore[arg-type]

    @pytest.mark.parametrize("value", [-1, 11, 1000])
    def test_an_implausible_count_is_rejected(self, value: int) -> None:
        with pytest.raises(ValidationError):
            Settings(_env_file=None, trusted_proxy_count=value)  # type: ignore[arg-type]

    def test_it_is_visible_in_the_public_configuration_summary(self) -> None:
        # The effective policy decides whether lockout and audit addresses mean
        # anything, so it belongs in the operator-facing summary.
        summary: dict[str, Any] = Settings(
            _env_file=None, trusted_proxy_count=2  # type: ignore[arg-type]
        ).public_summary()
        assert summary["trusted_proxy_count"] == 2

    def test_it_is_not_disclosed_over_the_public_api(self, client: TestClient) -> None:
        # `public_summary` is the operator-facing view; `/meta` is unauthenticated
        # and picks fields from it individually. How many proxies a deployment
        # runs is not something an anonymous caller needs to know.
        response = client.get("/api/v1/meta")
        assert response.status_code == 200
        assert "trusted_proxy" not in response.text.lower()
