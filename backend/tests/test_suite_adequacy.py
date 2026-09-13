"""Audits the test suite itself rather than the application.

A testing phase can leave a suite that is large, fast and green while quietly
missing whole surfaces. These tests check the suite as an artefact:

* every API route is referenced by at least one test, so a new endpoint cannot
  ship untested;
* the evaluation set is balanced across the roles and covers every domain value,
  because a set skewed to one role proves much less than its size suggests;
* the security-marked subset actually covers the security surface, so
  `pytest -m security` is a meaningful gate rather than a convenient label.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from app.api.router import api_router
from app.core.enums import Intent, RiskLevel, Role

BACKEND_DIR = Path(__file__).resolve().parents[1]
TESTS_DIR = BACKEND_DIR / "tests"
EVALUATION_SET = TESTS_DIR / "data" / "evaluation_questions.json"


def _test_corpus() -> str:
    """Every test file concatenated, for whole-suite reference checks."""
    parts = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _api_routes() -> list[tuple[tuple[str, ...], str]]:
    return sorted(
        {
            (tuple(sorted(getattr(route, "methods", set()) - {"HEAD", "OPTIONS"})), route.path)
            for route in api_router.routes
            if getattr(route, "path", "").startswith("/api")
        }
    )


class TestEveryRouteIsExercised:
    def test_no_route_is_unreferenced(self) -> None:
        corpus = _test_corpus()
        missing: list[str] = []

        for methods, path in _api_routes():
            # A path parameter is written as an f-string placeholder in the tests,
            # so {name} has to match "anything" rather than the literal braces.
            pattern = re.sub(r"\\\{[^}]+\\\}", "[^\"']*", re.escape(path))
            if not re.search(pattern, corpus):
                missing.append(f"{','.join(methods)} {path}")

        assert not missing, "these routes are not referenced by any test:\n  " + "\n  ".join(
            missing
        )

    def test_the_audit_would_notice_a_new_route(self) -> None:
        """The check must be capable of failing.

        The obvious way to write this - assert a made-up path is absent from the
        corpus - does not work, because the made-up path is written *in this file*
        and the corpus is every test file including this one. It failed on itself
        the first time. Instead: confirm the extraction found the real routes, and
        that a known route is genuinely matched by the same pattern the audit uses.
        """
        routes = _api_routes()
        assert len(routes) >= 30, len(routes)

        known = "/api/v1/knowledge/search"
        assert any(path == known for _methods, path in routes), "route extraction is broken"
        pattern = re.sub(r"\\\{[^}]+\\\}", "[^\"']*", re.escape(known))
        assert re.search(pattern, _test_corpus()), "the matching pattern finds nothing at all"

    def test_a_parameterised_route_is_matched_through_its_placeholder(self) -> None:
        # Tests call these through f-strings, so the pattern has to allow anything
        # where the placeholder is. Without this the audit reported two routes as
        # untested when they are among the best covered in the suite.
        known = "/api/v1/chat/conversations/{conversation_id}/messages"
        pattern = re.sub(r"\\\{[^}]+\\\}", "[^\"']*", re.escape(known))
        assert re.search(pattern, _test_corpus())


class TestTheEvaluationSetIsAdequate:
    @pytest.fixture(scope="class")
    def entries(self) -> list[dict]:
        return json.loads(EVALUATION_SET.read_text(encoding="utf-8"))["questions"]

    def test_it_meets_the_specification_minimum(self, entries: list[dict]) -> None:
        # PRODUCT_SPEC.md section 9 criterion 12 asks for at least 30.
        assert len(entries) >= 30, len(entries)

    def test_every_role_asks_questions(self, entries: list[dict]) -> None:
        # The product's central claim is that the same question is answered from a
        # different set of documents per role, so a set that only asks as an
        # employee cannot support that claim.
        by_role = Counter(entry["role"] for entry in entries)
        for role in (member.value for member in Role):
            assert by_role[role] > 0, f"no question is asked by {role}"
        # Not merely present: the restricted-knowledge roles need real coverage.
        assert by_role["it"] >= 5, by_role
        assert by_role["security"] >= 3, by_role

    def test_it_covers_every_intent(self, entries: list[dict]) -> None:
        covered = {entry["expected"]["intent"] for entry in entries}
        missing = {member.value for member in Intent} - covered
        assert not missing, f"no question exercises intent {missing}"

    def test_it_covers_every_risk_level(self, entries: list[dict]) -> None:
        covered = {entry["expected"]["risk_level"] for entry in entries}
        missing = {member.value for member in RiskLevel} - covered
        assert not missing, f"no question exercises risk level {missing}"

    def test_it_covers_the_specification_scenarios(self, entries: list[dict]) -> None:
        # PRODUCT_SPEC.md section 2 lists scenarios A to D.
        scenarios = {entry["scenario"] for entry in entries}
        for scenario in ("A", "B", "C", "D"):
            assert scenario in scenarios, f"scenario {scenario} is not covered"

    def test_it_asserts_the_safety_properties_at_least_once(self, entries: list[dict]) -> None:
        assert sum(1 for e in entries if e["expected"]["escalation"]) >= 5
        assert sum(1 for e in entries if e["expected"]["ticket"]) >= 5
        assert sum(1 for e in entries if e["expected"]["blocked"]) >= 3

    def test_it_still_records_known_gaps_rather_than_hiding_them(
        self, entries: list[dict]
    ) -> None:
        # The set documents the product's honest limits - an English-only knowledge
        # base, a topic with no document. Those entries exist to be reported, not
        # tuned away, so their disappearance is a signal worth failing on.
        notes = " ".join(entry.get("notes", "") for entry in entries).lower()
        assert "limitation" in " ".join(e["scenario"] for e in entries) or "gap" in notes or (
            "language" in notes
        ), "the set no longer records any known limitation"

    def test_every_graded_question_names_a_real_document(self, entries: list[dict]) -> None:
        from app.core.config import get_settings
        from app.rag.loader import load_documents

        documents, errors = load_documents(get_settings().knowledge_base_dir)
        assert documents and not errors
        known = {document.document_id for document in documents}

        unknown = [
            (entry["id"], doc)
            for entry in entries
            for doc in entry["expected"].get("documents_any_of", [])
            if doc not in known
        ]
        assert not unknown, f"expectations cite documents that do not exist: {unknown}"

    def test_the_thresholds_are_stated(self) -> None:
        metrics = json.loads(EVALUATION_SET.read_text(encoding="utf-8"))["metrics"]
        # Safety properties must be absolute; quality properties may have thresholds.
        assert metrics["escalation_accuracy_required"] == 1.0
        assert metrics["blocking_accuracy_required"] == 1.0
        assert 0.0 < metrics["intent_accuracy_min"] <= 1.0
        assert 0.0 < metrics["risk_accuracy_min"] <= 1.0
        assert 0.0 < metrics["retrieval_recall_min"] <= 1.0


class TestTheSecuritySubsetIsMeaningful:
    def test_it_covers_every_security_area(self) -> None:
        """`pytest -m security` is a gate, so it must span the whole surface.

        A marker that only lands on, say, RBAC tests would let the suite report a
        large "security" number while leaving injection and leakage unguarded.
        """
        areas = {
            "rbac": "test_rag_rbac.py",
            "authorization matrix": "test_authorization_matrix.py",
            "prompt injection": "test_prompt_guard.py",
            "redaction": "test_redaction.py",
            "sessions": "test_auth_sessions.py",
            "login lockout": "test_login_guard.py",
            "client address": "test_client_address.py",
            "config guardrails": "test_config.py",
            "security primitives": "test_security_primitives.py",
            "ticket scoping": "test_ticket_api.py",
            "dashboard exposure": "test_phase7_qa_dashboard.py",
            "deployment hardening": "test_deployment_assets.py",
        }
        unmarked = []
        for area, filename in areas.items():
            source = (TESTS_DIR / filename).read_text(encoding="utf-8")
            if "pytest.mark.security" not in source:
                unmarked.append(f"{area} ({filename})")
        assert not unmarked, f"these security areas are not in the -m security subset: {unmarked}"
