"""The evaluation set: 40 questions run through the whole pipeline.

This is the specification's "at least 30 test questions" requirement, and it is
deliberately run through the **chat API** rather than by calling the classifiers
directly: the point is to evaluate the product, not the units.

Quality metrics (intent, risk, retrieval) have tolerance thresholds. Two
properties do not:

* **escalation** must be exactly right. A high-risk event that fails to reach a
  human is the failure this product exists to prevent, and a low-risk question
  that raises a ticket wastes a person's time.
* **blocking** must be exactly right. An injection attempt that gets through is
  the whole defence failing.

When a question misses, the failure output names the question, the expectation
and what actually happened, so the set is a debugging tool rather than a score.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD

pytestmark = pytest.mark.evaluation

DATA_FILE = Path(__file__).parent / "data" / "evaluation_questions.json"


def load_questions() -> list[dict[str, Any]]:
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))["questions"]


def load_metrics() -> dict[str, float]:
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))["metrics"]


QUESTIONS = load_questions()
METRICS = load_metrics()


def question_ids() -> list[str]:
    return [entry["id"] for entry in QUESTIONS]


class Pipeline:
    """Runs evaluation questions against the API and records the outcomes."""

    def __init__(self, client: TestClient) -> None:
        self._client = client
        self._headers: dict[str, dict[str, str]] = {}
        self.results: list[dict[str, Any]] = []

    def _headers_for(self, role: str) -> dict[str, str]:
        if role not in self._headers:
            response = self._client.post(
                "/api/v1/auth/login",
                json={"email": DEMO_ACCOUNTS[role], "password": DEMO_PASSWORD},
            )
            assert response.status_code == 200, response.text
            self._headers[role] = {"Authorization": f"Bearer {response.json()['access_token']}"}
        return self._headers[role]

    def _fresh_conversation(self, role: str) -> int:
        """A new conversation per question.

        Escalation is *sticky* within a conversation: once a turn is assessed as
        high, later turns stay escalated, which is correct product behaviour.
        Sharing one conversation across the set would therefore let an early
        question contaminate every later one - so each question gets its own.
        """
        response = self._client.post(
            "/api/v1/chat/conversations", headers=self._headers_for(role), json={}
        )
        assert response.status_code == 201, response.text
        return int(response.json()["id"])

    def ask(self, entry: dict[str, Any]) -> dict[str, Any]:
        role = entry["role"]
        headers = self._headers_for(role)
        conversation_id = self._fresh_conversation(role)
        response = self._client.post(
            f"/api/v1/chat/conversations/{conversation_id}/messages",
            headers=headers,
            json={"content": entry["question"]},
        )
        assert response.status_code == 200, f"{entry['id']}: {response.text}"
        payload = response.json()["assistant_message"]["payload"]
        expected = entry["expected"]

        documents = [source["document_id"] for source in payload["source_documents"]]
        wanted = expected.get("documents_any_of", [])
        result = {
            "id": entry["id"],
            "role": role,
            "question": entry["question"],
            "expected_intent": expected["intent"],
            "actual_intent": payload["intent"],
            "intent_ok": payload["intent"] == expected["intent"],
            "expected_risk": expected["risk_level"],
            "actual_risk": payload["risk_level"],
            "risk_ok": payload["risk_level"] == expected["risk_level"],
            "expected_escalation": expected["escalation"],
            "actual_escalation": payload["human_escalation"],
            "escalation_ok": payload["human_escalation"] == expected["escalation"],
            "expected_ticket": expected["ticket"],
            "actual_ticket": payload["ticket_reference"] is not None,
            "ticket_ok": (payload["ticket_reference"] is not None) == expected["ticket"],
            "expected_blocked": expected["blocked"],
            "actual_blocked": payload["blocked"],
            "blocked_ok": payload["blocked"] == expected["blocked"],
            "documents": documents,
            "wanted_documents": wanted,
            "retrieval_ok": (not wanted) or bool(set(documents) & set(wanted)),
            "grounded": payload["grounded"],
        }
        expected_grounded = expected.get("grounded")
        result["expected_grounded"] = expected_grounded
        result["grounded_ok"] = (
            True if expected_grounded is None else payload["grounded"] == expected_grounded
        )
        self.results.append(result)
        return result

    def run_all(self) -> list[dict[str, Any]]:
        if not self.results:
            for entry in QUESTIONS:
                self.ask(entry)
        return self.results


@pytest.fixture(scope="module")
def evaluation(request) -> Pipeline:
    """Run the whole set once and share the results across the assertions.

    Module-scoped because running 40 questions through the API is the expensive
    part, and every assertion below reads the same recorded outcomes.
    """
    from fastapi.testclient import TestClient as _TestClient

    from app.core.config import Settings
    from app.db.session import reset_engine_cache
    from app.main import create_app

    # Build settings and a client here rather than using the function-scoped
    # fixtures, so the whole set shares one database and one index.
    from tests.conftest import BACKEND_DIR

    env = {
        "APP_ENV": "test",
        "DEBUG": "true",
        "LOG_LEVEL": "WARNING",
        "DATABASE_URL": f"sqlite:///{(request.config.rootpath / 'evaluation.db').as_posix()}",
        "AUTH_SECRET_KEY": "evaluation-suite-key-not-for-production-use",
        "ALLOW_DEMO_LOGIN": "true",
        "SEED_DEMO_USERS": "true",
        "DEMO_USER_PASSWORD": DEMO_PASSWORD,
        "PASSWORD_HASH_ROUNDS": "4",
        "LLM_PROVIDER": "mock",
        "EMBEDDING_PROVIDER": "tfidf",
        "VECTOR_STORE": "memory",
        "RETRIEVAL_TOP_K": "6",
        "RETRIEVAL_MIN_SCORE": "0.05",
        "RETRIEVAL_RELATIVE_FLOOR": "0.5",
        "RETRIEVAL_MAX_PER_DOCUMENT": "2",
        "CHAT_RATE_LIMIT_PER_MINUTE": "10000",
    }
    del BACKEND_DIR

    import os

    previous = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    from app.core.config import get_settings

    get_settings.cache_clear()
    reset_engine_cache()
    settings = Settings()

    database = Path(env["DATABASE_URL"].removeprefix("sqlite:///"))
    database.unlink(missing_ok=True)
    # A vector store directory inside the run directory keeps the suite isolated.
    settings = settings.model_copy(
        update={"vector_store_path": str(database.parent / "vector_store")}
    )

    app = create_app(settings)
    with _TestClient(app, raise_server_exceptions=False) as client:
        pipeline = Pipeline(client)
        pipeline.run_all()
        yield pipeline

    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()
    reset_engine_cache()


def report(results: list[dict[str, Any]]) -> str:
    """A readable table of every question and its outcome."""
    lines = [
        f"{'id':<14} {'role':<9} {'intent':<18} {'risk':<9} {'esc':<4} {'blk':<4} {'doc':<5} question",
        "-" * 120,
    ]
    for item in results:
        lines.append(
            f"{item['id']:<14} {item['role']:<9} "
            f"{'ok ' if item['intent_ok'] else 'MISS'}{item['actual_intent']:<14} "
            f"{'ok ' if item['risk_ok'] else 'MISS'}{item['actual_risk']:<5} "
            f"{'ok' if item['escalation_ok'] else 'XX':<4} "
            f"{'ok' if item['blocked_ok'] else 'XX':<4} "
            f"{'ok' if item['retrieval_ok'] else 'MISS':<5} "
            f"{item['question'][:58]}"
        )
    return "\n".join(lines)


class TestEvaluationSetIntegrity:
    """The set itself must be well-formed before its results mean anything."""

    def test_at_least_thirty_questions(self) -> None:
        assert len(QUESTIONS) >= 30, "the specification requires at least 30 questions"

    def test_ids_are_unique(self) -> None:
        ids = question_ids()
        assert len(ids) == len(set(ids))

    def test_every_question_declares_the_full_expectation(self) -> None:
        for entry in QUESTIONS:
            assert entry["role"] in {"employee", "it", "security"}, entry["id"]
            assert len(entry["question"]) >= 10, entry["id"]
            expected = entry["expected"]
            for key in (
                "intent",
                "risk_level",
                "escalation",
                "ticket",
                "blocked",
                "documents_any_of",
            ):
                assert key in expected, f"{entry['id']} is missing {key}"

    def test_all_four_specification_scenarios_are_covered(self) -> None:
        scenarios = {entry["scenario"] for entry in QUESTIONS}
        assert {"A", "B", "C", "D"} <= scenarios

    def test_every_metric_is_declared(self) -> None:
        assert set(METRICS) >= {
            "intent_accuracy_min",
            "risk_accuracy_min",
            "retrieval_recall_min",
            "escalation_accuracy_required",
            "blocking_accuracy_required",
        }


class TestSafetyProperties:
    """Escalation and blocking must be perfect: they are not quality metrics."""

    def test_escalation_is_always_correct(self, evaluation: Pipeline) -> None:
        wrong = [item for item in evaluation.results if not item["escalation_ok"]]
        detail = "\n".join(
            f"  {item['id']}: expected escalation={item['expected_escalation']}, "
            f"got {item['actual_escalation']} (risk {item['actual_risk']}) - {item['question']}"
            for item in wrong
        )
        assert not wrong, f"{len(wrong)} escalation mistakes:\n{detail}"

    def test_ticket_creation_follows_the_escalation_rule(self, evaluation: Pipeline) -> None:
        wrong = [item for item in evaluation.results if not item["ticket_ok"]]
        detail = "\n".join(
            f"  {item['id']}: expected ticket={item['expected_ticket']}, "
            f"got {item['actual_ticket']} - {item['question']}"
            for item in wrong
        )
        assert not wrong, f"{len(wrong)} ticket mistakes:\n{detail}"

    def test_injection_attempts_are_always_blocked(self, evaluation: Pipeline) -> None:
        attempts = [item for item in evaluation.results if item["expected_blocked"]]
        wrong = [item for item in attempts if not item["blocked_ok"]]
        assert attempts, "the set must contain adversarial cases"
        assert not wrong, "\n".join(f"  {item['id']} was not blocked" for item in wrong)

    def test_ordinary_questions_are_never_blocked(self, evaluation: Pipeline) -> None:
        ordinary = [item for item in evaluation.results if not item["expected_blocked"]]
        wrong = [item for item in ordinary if not item["blocked_ok"]]
        assert not wrong, "\n".join(
            f"  {item['id']} was wrongly blocked - {item['question']}" for item in wrong
        )

    def test_a_negated_credential_never_escalates(self, evaluation: Pipeline) -> None:
        for item in evaluation.results:
            if item["id"].startswith("negation-"):
                assert item["actual_escalation"] is False, item["id"]
                assert item["actual_risk"] in {"low", "medium"}, item["id"]


class TestQualityMetrics:
    def test_intent_accuracy(self, evaluation: Pipeline) -> None:
        results = evaluation.results
        correct = sum(1 for item in results if item["intent_ok"])
        accuracy = correct / len(results)
        misses = [item for item in results if not item["intent_ok"]]
        detail = "\n".join(
            f"  {item['id']}: expected {item['expected_intent']}, got {item['actual_intent']}"
            f" - {item['question'][:70]}"
            for item in misses
        )
        assert accuracy >= METRICS["intent_accuracy_min"], (
            f"intent accuracy {accuracy:.2%} is below {METRICS['intent_accuracy_min']:.0%}\n"
            f"{detail}"
        )

    def test_risk_accuracy(self, evaluation: Pipeline) -> None:
        results = evaluation.results
        correct = sum(1 for item in results if item["risk_ok"])
        accuracy = correct / len(results)
        misses = [item for item in results if not item["risk_ok"]]
        detail = "\n".join(
            f"  {item['id']}: expected {item['expected_risk']}, got {item['actual_risk']}"
            f" - {item['question'][:70]}"
            for item in misses
        )
        assert (
            accuracy >= METRICS["risk_accuracy_min"]
        ), f"risk accuracy {accuracy:.2%} is below {METRICS['risk_accuracy_min']:.0%}\n{detail}"

    def test_retrieval_recall(self, evaluation: Pipeline) -> None:
        scoped = [item for item in evaluation.results if item["wanted_documents"]]
        correct = sum(1 for item in scoped if item["retrieval_ok"])
        recall = correct / len(scoped)
        misses = [item for item in scoped if not item["retrieval_ok"]]
        detail = "\n".join(
            f"  {item['id']}: wanted one of {item['wanted_documents']}, got {item['documents']}"
            f" - {item['question'][:60]}"
            for item in misses
        )
        assert recall >= METRICS["retrieval_recall_min"], (
            f"retrieval recall {recall:.2%} is below {METRICS['retrieval_recall_min']:.0%}\n"
            f"{detail}"
        )

    def test_ungrounded_questions_say_so(self, evaluation: Pipeline) -> None:
        """When the answer is not in the knowledge base, the assistant must admit it."""
        checked = [item for item in evaluation.results if item["expected_grounded"] is False]
        assert checked, "the set must contain an unanswerable question"
        wrong = [item for item in checked if not item["grounded_ok"]]
        assert not wrong, "\n".join(
            f"  {item['id']} claimed to be grounded - {item['question']}" for item in wrong
        )

    def test_report_is_printed(self, evaluation: Pipeline, capsys) -> None:
        """Not an assertion so much as a deliverable: the set prints its own report."""
        text = report(evaluation.results)
        print("\n" + text)
        captured = capsys.readouterr()
        assert "question" in captured.out
        results = evaluation.results
        print(
            f"\nsummary: {len(results)} questions | "
            f"intent {sum(1 for i in results if i['intent_ok'])}/{len(results)} | "
            f"risk {sum(1 for i in results if i['risk_ok'])}/{len(results)} | "
            f"retrieval {sum(1 for i in results if i['retrieval_ok'])}/{len(results)} | "
            f"escalation {sum(1 for i in results if i['escalation_ok'])}/{len(results)} | "
            f"blocked {sum(1 for i in results if i['blocked_ok'])}/{len(results)}"
        )


class TestPerQuestionOutcomes:
    """One parametrised case per question, so a failure names the question."""

    @pytest.mark.parametrize("entry", QUESTIONS, ids=question_ids())
    def test_question_behaves_as_expected(self, evaluation: Pipeline, entry: dict) -> None:
        result = next(item for item in evaluation.results if item["id"] == entry["id"])
        problems = []
        if not result["intent_ok"]:
            problems.append(
                f"intent: expected {result['expected_intent']}, got {result['actual_intent']}"
            )
        if not result["risk_ok"]:
            problems.append(
                f"risk: expected {result['expected_risk']}, got {result['actual_risk']}"
            )
        if not result["escalation_ok"]:
            problems.append(
                f"escalation: expected {result['expected_escalation']}, "
                f"got {result['actual_escalation']}"
            )
        if not result["blocked_ok"]:
            problems.append(
                f"blocked: expected {result['expected_blocked']}, got {result['actual_blocked']}"
            )
        if not result["retrieval_ok"]:
            problems.append(
                f"retrieval: wanted one of {result['wanted_documents']}, got {result['documents']}"
            )
        assert not problems, f"{entry['id']} - {entry['question']}\n  " + "\n  ".join(problems)
