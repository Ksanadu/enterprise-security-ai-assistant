"""Runs the demo script against an in-process application.

`scripts/demo.py` is the project's executable demo documentation. Documentation
that is never executed rots, so this module runs the whole thing - every scenario
and every assertion it makes - through the same ``run_demo`` entry point the CLI
uses. The only difference is the transport: the CLI talks to a live server over
the network, these tests use Starlette's ``TestClient``.

If someone changes a response shape, an intent label or a policy threshold and
forgets the demo, this fails.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.db.session import reset_engine_cache
from app.main import create_app
from tests.conftest import DEMO_PASSWORD

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEMO_SCRIPT = BACKEND_DIR / "scripts" / "demo.py"
if str(BACKEND_DIR / "scripts") not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR / "scripts"))

import demo as demo_script  # noqa: E402  (the path above must be set first)

pytestmark = [pytest.mark.evaluation]


@pytest.fixture(scope="module")
def demo_app(_settings_env: dict[str, str], tmp_path_factory: pytest.TempPathFactory) -> Iterator[FastAPI]:
    """An isolated application for the demo, with its own SQLite file.

    Module-scoped so the demo runs once, but it must not pick up the developer's
    real `.env` or write into `backend/data/app.db`, so the environment is applied
    explicitly with a private `MonkeyPatch` instead of the function-scoped
    `monkeypatch` fixture.
    """
    patcher = pytest.MonkeyPatch()
    for key, value in _settings_env.items():
        patcher.setenv(key, value)
    directory = tmp_path_factory.mktemp("demo")
    patcher.setenv("DATABASE_URL", f"sqlite:///{(directory / 'demo.db').as_posix()}")

    get_settings.cache_clear()
    reset_engine_cache()
    application = create_app(get_settings())
    try:
        yield application
    finally:
        reset_engine_cache()
        get_settings.cache_clear()
        patcher.undo()


@pytest.fixture(scope="module")
def settings_for_demo(demo_app: FastAPI) -> Settings:
    return get_settings()


@pytest.fixture(scope="module")
def report(demo_app: FastAPI) -> demo_script.Report:
    """Run the complete demo once for the whole module.

    It posts about a dozen questions, so repeating it per test would be wasteful;
    the report is read-only afterwards.
    """
    assert DEMO_PASSWORD, "the demo signs in with the documented demo password"
    with TestClient(demo_app, raise_server_exceptions=False) as client:
        return demo_script.run_demo(
            client, echo=lambda _: None, password=DEMO_PASSWORD, quiet=True
        )


class TestTheDemoItselfPasses:
    def test_every_check_passed(self, report: demo_script.Report) -> None:
        failures = [f"{check.label} (observed: {check.observed})" for check in report.failures]
        assert not failures, "the demo reported failures:\n  " + "\n  ".join(failures)

    def test_it_exercised_a_meaningful_number_of_checks(self, report: demo_script.Report) -> None:
        # Guards against the demo silently degenerating into two trivial checks.
        assert len(report.checks) >= 40, len(report.checks)

    def test_it_covers_every_documented_scenario(self, report: demo_script.Report) -> None:
        titles = [title for title, _ in report.scenarios]
        assert len(titles) == 9, titles
        for marker in ("SCENARIO A", "SCENARIO B", "SCENARIO C", "SCENARIO D"):
            assert any(marker in title for title in titles), marker
        # The mandatory flow, role scoping and "what it refuses to do".
        assert any("section 10" in title for title in titles)
        assert any("three roles" in title for title in titles)
        assert any("refuses" in title for title in titles)


class TestTheDemoFindsRealBehaviour:
    """Spot-check the substance, not merely that nothing raised."""

    @pytest.fixture(scope="class")
    def observed(self, report: demo_script.Report) -> dict[str, str]:
        return {check.label: check.observed for check in report.checks}

    def test_the_mandatory_flow_escalated_and_filed_a_ticket(
        self, observed: dict[str, str]
    ) -> None:
        assert observed["F.3 risk still Low - nothing has happened yet"] == "low"
        assert observed["F.6 risk rose to High"] == "high"
        assert observed["F.9 Security Ticket created"].startswith("SEC-")
        assert observed["F.10 the ticket went to the security queue"].startswith("SEC-")
        assert observed["ticket closed by the security team"] == "closed"

    def test_the_risk_was_driven_by_a_named_signal(self, observed: dict[str, str]) -> None:
        assert "credentials_submitted" in observed["F.7 a credential signal was detected"]

    def test_access_control_and_audit_scenarios_ran(self, report: demo_script.Report) -> None:
        labels = {check.label for check in report.checks}
        assert "the escalation is audited against this ticket" in labels
        assert "the restricted document is filtered out before scoring" in labels
        assert "employee cannot change a ticket they do not own" in labels
        assert "dashboard refused to a non-security role" in labels

    def test_cross_employee_isolation_is_probed_not_assumed(
        self, observed: dict[str, str]
    ) -> None:
        # This check used to assert `isinstance(x, set)`, which is true no matter
        # what the API does. It now has to observe a real refusal.
        assert observed["the first employee cannot read it"] == "HTTP 404"
        assert observed["the second employee can read their own ticket"] == ""
        assert "own ticket(s) visible" in observed["and it does not appear in their list"]

    def test_no_check_passes_on_a_tautology(self, report: demo_script.Report) -> None:
        """Every failing check must be able to fail.

        A cheap structural guard: a check whose recorded observation is empty for
        a boolean comparison is fine, but no check may compare a value to itself.
        """
        source = (BACKEND_DIR / "scripts" / "demo.py").read_text(encoding="utf-8")
        assert "isinstance(" not in source, "a tautological assertion crept back into the demo"

    def test_the_documented_check_count_is_the_real_one(self, report: demo_script.Report) -> None:
        # Both the README and the demo guide state how many checks the demo
        # makes. Documentation that quotes a number nothing verifies is how
        # "67 checks" quietly becomes wrong.
        actual = len(report.checks)
        project_root = BACKEND_DIR.parent
        for name, path in (
            ("README.md", project_root / "README.md"),
            ("docs/DEMO.md", project_root / "docs" / "DEMO.md"),
        ):
            text = path.read_text(encoding="utf-8")
            assert f"{actual} checks" in text, (
                f"{name} does not state the real check count ({actual})"
            )

    def test_the_demo_used_an_isolated_database(self, settings_for_demo: Settings) -> None:
        # A demo test that wrote into the developer's real database would be a
        # nasty surprise, so assert the isolation rather than assume it.
        assert "demo" in str(settings_for_demo.sqlite_path)


class TestTheCommandLine:
    def test_it_reports_a_clear_error_when_nothing_is_listening(self, capsys) -> None:
        # Port 1 is not reachable, which exercises the "server is down" path
        # without waiting for a real timeout.
        code = demo_script.main(["--base-url", "http://127.0.0.1:1", "--timeout", "2"])
        assert code == 2
        captured = capsys.readouterr()
        assert "Cannot reach the API" in captured.err
        assert "uvicorn" in captured.err

    def test_the_default_target_matches_the_documented_backend_port(self) -> None:
        source = (BACKEND_DIR / "scripts" / "demo.py").read_text(encoding="utf-8")
        for flag in ("--base-url", "--password", "--quiet", "--timeout"):
            assert flag in source, flag
        assert "http://127.0.0.1:8000" in source

    def test_the_demo_waits_out_a_rate_limit_instead_of_failing(self) -> None:
        """A demonstration that cannot be repeated is a poor demonstration.

        The demo posts around a dozen questions and the default limit is 20 per
        minute per user, so a second run used to fail outright. The limit is a
        security control, so the fix is to respect it and wait for the window the
        server reports - never to raise or bypass it.
        """
        source = DEMO_SCRIPT.read_text(encoding="utf-8")
        assert "429" in source
        assert "time.sleep" in source
        assert "retry_after_seconds" in source
        # It must not disable or raise the limit to make itself pass.
        assert "CHAT_RATE_LIMIT_PER_MINUTE=" not in source
        assert "monkeypatch" not in source

    def test_the_wait_is_bounded(self) -> None:
        source = DEMO_SCRIPT.read_text(encoding="utf-8")
        assert "MAX_RATE_LIMIT_WAITS" in source
        assert "min(seconds" in source, "an unbounded wait could hang a CI job"
