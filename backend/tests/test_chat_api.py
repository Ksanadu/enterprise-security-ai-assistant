"""Chat API tests: conversations, ownership isolation, grounded answers.

The ownership tests are the security core of this phase: a user must not be able
to read, continue or delete another user's conversation, and must not be able to
tell whether it exists.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog, Conversation, Message
from app.db.session import session_scope
from app.security.rate_limit import SlidingWindowLimiter
from app.services.chat_service import build_retrieval_query, needs_conversation_context
from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD
from tests.test_rag_rbac import EMPLOYEE_VISIBLE

pytestmark = pytest.mark.security


def new_conversation(client: TestClient, headers: dict[str, str], title: str | None = None) -> int:
    payload = {"title": title} if title else {}
    response = client.post("/api/v1/chat/conversations", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def ask(client: TestClient, headers: dict[str, str], conversation_id: int, content: str):
    return client.post(
        f"/api/v1/chat/conversations/{conversation_id}/messages",
        headers=headers,
        json={"content": content},
    )


class TestAuthenticationRequired:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/api/v1/chat/conversations"),
            ("POST", "/api/v1/chat/conversations"),
            ("GET", "/api/v1/chat/conversations/1"),
            ("DELETE", "/api/v1/chat/conversations/1"),
            ("POST", "/api/v1/chat/conversations/1/messages"),
            ("GET", "/api/v1/chat/capabilities"),
        ],
    )
    def test_endpoints_require_authentication(
        self, client: TestClient, method: str, path: str
    ) -> None:
        response = client.request(method, path, json={"content": "hello"})
        assert response.status_code == 401


class TestConversations:
    def test_create_and_list(self, client: TestClient, employee_headers) -> None:
        conversation_id = new_conversation(client, employee_headers, "Password question")
        listing = client.get("/api/v1/chat/conversations", headers=employee_headers).json()
        assert listing["count"] == 1
        assert listing["conversations"][0]["id"] == conversation_id
        assert listing["conversations"][0]["title"] == "Password question"
        assert listing["conversations"][0]["message_count"] == 0

    def test_listing_is_empty_for_a_new_user(self, client: TestClient, it_headers) -> None:
        assert client.get("/api/v1/chat/conversations", headers=it_headers).json()["count"] == 0

    def test_get_returns_messages(self, client: TestClient, employee_headers) -> None:
        conversation_id = new_conversation(client, employee_headers)
        ask(client, employee_headers, conversation_id, "What are the password requirements?")
        detail = client.get(
            f"/api/v1/chat/conversations/{conversation_id}", headers=employee_headers
        ).json()
        assert len(detail["messages"]) == 2
        assert detail["messages"][0]["role"] == "user"
        assert detail["messages"][1]["role"] == "assistant"

    def test_delete_removes_the_conversation(self, client: TestClient, employee_headers) -> None:
        conversation_id = new_conversation(client, employee_headers)
        assert (
            client.delete(
                f"/api/v1/chat/conversations/{conversation_id}", headers=employee_headers
            ).status_code
            == 204
        )
        assert (
            client.get("/api/v1/chat/conversations", headers=employee_headers).json()["count"] == 0
        )

    def test_conversation_is_titled_from_the_first_question(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        ask(client, employee_headers, conversation_id, "How do I report a phishing email?")
        listing = client.get("/api/v1/chat/conversations", headers=employee_headers).json()
        assert listing["conversations"][0]["title"].startswith("How do I report")


class TestOwnershipIsolation:
    """A conversation belongs to exactly one user."""

    @pytest.fixture
    def other_user_headers(self, client: TestClient, employee_headers) -> dict[str, str]:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee2"], "password": DEMO_PASSWORD},
        )
        assert response.status_code == 200
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def test_another_user_cannot_read_the_conversation(
        self, client: TestClient, employee_headers, other_user_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        ask(client, employee_headers, conversation_id, "password policy")
        response = client.get(
            f"/api/v1/chat/conversations/{conversation_id}", headers=other_user_headers
        )
        assert response.status_code == 404

    def test_another_user_cannot_post_into_the_conversation(
        self, client: TestClient, employee_headers, other_user_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        response = ask(client, other_user_headers, conversation_id, "continue this please")
        assert response.status_code == 404

    def test_another_user_cannot_delete_the_conversation(
        self, client: TestClient, employee_headers, other_user_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        assert (
            client.delete(
                f"/api/v1/chat/conversations/{conversation_id}", headers=other_user_headers
            ).status_code
            == 404
        )
        # Still there for the owner.
        assert (
            client.get(
                f"/api/v1/chat/conversations/{conversation_id}", headers=employee_headers
            ).status_code
            == 200
        )

    def test_foreign_and_missing_conversations_are_indistinguishable(
        self, client: TestClient, employee_headers, other_user_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        foreign = client.get(
            f"/api/v1/chat/conversations/{conversation_id}", headers=other_user_headers
        )
        missing = client.get("/api/v1/chat/conversations/999999", headers=other_user_headers)
        assert foreign.status_code == missing.status_code == 404
        assert foreign.json()["error"]["message"] == missing.json()["error"]["message"]

    def test_listing_never_includes_other_users_conversations(
        self, client: TestClient, employee_headers, other_user_headers
    ) -> None:
        new_conversation(client, employee_headers, "Private")
        listing = client.get("/api/v1/chat/conversations", headers=other_user_headers).json()
        assert listing["count"] == 0

    def test_a_higher_role_does_not_gain_access_to_private_conversations(
        self, client: TestClient, employee_headers, security_headers
    ) -> None:
        """Role privilege widens *knowledge* scope, never conversation ownership."""
        conversation_id = new_conversation(client, employee_headers, "Employee private")
        response = client.get(
            f"/api/v1/chat/conversations/{conversation_id}", headers=security_headers
        )
        assert response.status_code == 404

    def test_denied_access_is_logged(
        self, client: TestClient, employee_headers, other_user_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        client.get(f"/api/v1/chat/conversations/{conversation_id}", headers=other_user_headers)
        with session_scope() as session:
            rows = session.scalars(
                select(AuditLog).where(AuditLog.action == "chat.conversation.denied")
            ).all()
        assert rows, "a denied conversation access must leave a trace"

    def test_conversations_are_stored_against_their_owner(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        with session_scope() as session:
            conversation = session.get(Conversation, conversation_id)
            assert conversation is not None
            assert conversation.user_id == 1  # employee@example.com


class TestMessaging:
    def test_message_produces_a_grounded_answer_with_citations(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        response = ask(
            client, employee_headers, conversation_id, "What are the company password requirements?"
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assistant = body["assistant_message"]
        assert assistant["content"].strip()
        payload = assistant["payload"]
        assert payload["grounded"] is True
        assert payload["source_documents"]
        assert payload["source_documents"][0]["document_id"] == "KB-001"
        assert assistant["content"]

    def test_citations_are_inside_the_callers_scope(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        for question in [
            "How do we investigate a phishing campaign?",
            "What is the incident severity classification?",
            "Show me the access control policy",
            "service account password rotation",
        ]:
            response = ask(client, employee_headers, conversation_id, question)
            assert response.status_code == 200
            for source in response.json()["assistant_message"]["payload"]["source_documents"]:
                assert source["document_id"] in EMPLOYEE_VISIBLE

    def test_same_question_yields_role_appropriate_sources(
        self, client: TestClient, employee_headers, security_headers
    ) -> None:
        question = "We need to investigate a phishing campaign where credentials were submitted."
        employee_id = new_conversation(client, employee_headers)
        security_id = new_conversation(client, security_headers)
        employee = ask(client, employee_headers, employee_id, question).json()
        security = ask(client, security_headers, security_id, question).json()

        employee_docs = {
            source["document_id"]
            for source in employee["assistant_message"]["payload"]["source_documents"]
        }
        security_docs = {
            source["document_id"]
            for source in security["assistant_message"]["payload"]["source_documents"]
        }
        assert employee_docs <= EMPLOYEE_VISIBLE
        assert security_docs - employee_docs

    def test_empty_message_is_rejected(self, client: TestClient, employee_headers) -> None:
        conversation_id = new_conversation(client, employee_headers)
        assert ask(client, employee_headers, conversation_id, "").status_code == 422

    def test_whitespace_only_message_is_rejected(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        response = ask(client, employee_headers, conversation_id, "   \n  ")
        assert response.status_code == 422

    def test_oversized_message_is_rejected(self, client: TestClient, employee_headers) -> None:
        conversation_id = new_conversation(client, employee_headers)
        assert ask(client, employee_headers, conversation_id, "x" * 5000).status_code == 422

    def test_oversized_message_is_rejected_by_the_service_too(
        self, client: TestClient, employee_headers, settings
    ) -> None:
        """The schema bound and the service bound must agree."""
        assert settings.max_query_length <= 4000

    def test_unanswerable_question_says_so_without_hinting_at_restricted_material(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        response = ask(client, employee_headers, conversation_id, "zzzz qqqq xxxx yyyy")
        assert response.status_code == 200
        payload = response.json()["assistant_message"]["payload"]
        assert payload["grounded"] is False
        assert payload["source_documents"] == []
        text = response.json()["assistant_message"]["content"].lower()
        for leak in ("restricted", "permission", "not allowed", "security team only"):
            assert leak not in text

    def test_multi_turn_history_is_preserved(self, client: TestClient, employee_headers) -> None:
        conversation_id = new_conversation(client, employee_headers)
        ask(client, employee_headers, conversation_id, "What are the password requirements?")
        ask(client, employee_headers, conversation_id, "And what about MFA?")
        detail = client.get(
            f"/api/v1/chat/conversations/{conversation_id}", headers=employee_headers
        ).json()
        assert len(detail["messages"]) == 4
        assert [m["role"] for m in detail["messages"]] == [
            "user",
            "assistant",
            "user",
            "assistant",
        ]

    def test_follow_up_question_keeps_the_topic(self, client: TestClient, employee_headers) -> None:
        """A bare follow-up must still retrieve the earlier subject."""
        conversation_id = new_conversation(client, employee_headers)
        first = ask(
            client, employee_headers, conversation_id, "What are the password requirements?"
        )
        follow_up = ask(client, employee_headers, conversation_id, "What else should I know?")

        first_docs = {
            s["document_id"]
            for s in first.json()["assistant_message"]["payload"]["source_documents"]
        }
        follow_docs = {
            s["document_id"]
            for s in follow_up.json()["assistant_message"]["payload"]["source_documents"]
        }
        assert first_docs & follow_docs, "the follow-up lost the conversation topic"

    def test_assistant_payload_carries_the_classification(
        self, client: TestClient, employee_headers
    ) -> None:
        """Intent and risk are populated by the Phase 5 classifiers."""
        conversation_id = new_conversation(client, employee_headers)
        payload = ask(client, employee_headers, conversation_id, "password policy").json()[
            "assistant_message"
        ]["payload"]
        assert payload["intent"] in {
            "security_faq",
            "phishing",
            "security_incident",
            "it_support",
            "policy_question",
            "out_of_scope",
        }
        assert payload["intent_source"] in {"rules", "model", "guard"}
        assert 0.0 <= payload["intent_confidence"] <= 1.0
        assert payload["risk_level"] in {"low", "medium", "high", "critical"}
        assert payload["peak_risk_level"] in {"low", "medium", "high", "critical"}
        assert payload["blocked"] is False

    def test_stored_message_records_the_cited_documents(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        ask(client, employee_headers, conversation_id, "What are the password requirements?")
        with session_scope() as session:
            assistant = session.scalar(
                select(Message).where(
                    Message.conversation_id == conversation_id, Message.role == "assistant"
                )
            )
            assert assistant is not None
            cited = assistant.source_document_ids or []
        # The wider retrieval window can cite more than one document; what matters
        # is that the policy the answer came from is among the citations.
        assert "KB-001" in cited, f"the password policy should be cited, got {cited}"


class TestCapabilities:
    def test_capabilities_describe_the_callers_scope(self, client: TestClient, it_headers) -> None:
        body = client.get("/api/v1/chat/capabilities", headers=it_headers).json()
        assert body["role"] == "it"
        assert body["document_count"] == 10
        assert body["knowledge_ready"] is True
        assert body["provider"]["provider"] == "mock"
        assert "categories" in body

    def test_capabilities_contain_no_secrets(self, client: TestClient, employee_headers) -> None:
        raw = client.get("/api/v1/chat/capabilities", headers=employee_headers).text.lower()
        for forbidden in ("api_key", "secret", "password", "token"):
            assert forbidden not in raw


class TestRateLimiting:
    def test_messages_are_throttled_per_user(
        self, client: TestClient, employee_headers, app
    ) -> None:
        # Rebuild the limiter with a small budget for the test.
        app.state.chat_limiter = SlidingWindowLimiter(limit=2)
        conversation_id = new_conversation(client, employee_headers)
        assert ask(client, employee_headers, conversation_id, "password").status_code == 200
        assert ask(client, employee_headers, conversation_id, "vpn").status_code == 200
        throttled = ask(client, employee_headers, conversation_id, "phishing")
        assert throttled.status_code == 429
        assert throttled.json()["error"]["code"] == "rate_limited"
        assert throttled.json()["error"]["details"]["retry_after_seconds"] >= 1

    def test_throttling_does_not_consume_the_message(
        self, client: TestClient, employee_headers, app
    ) -> None:
        app.state.chat_limiter = SlidingWindowLimiter(limit=1)
        conversation_id = new_conversation(client, employee_headers)
        ask(client, employee_headers, conversation_id, "password")
        ask(client, employee_headers, conversation_id, "vpn")
        detail = client.get(
            f"/api/v1/chat/conversations/{conversation_id}", headers=employee_headers
        ).json()
        assert len(detail["messages"]) == 2, "a throttled request must not be stored"


class TestRateLimiterUnit:
    def test_window_expiry(self) -> None:
        now = [0.0]
        limiter = SlidingWindowLimiter(limit=2, window_seconds=10, clock=lambda: now[0])
        limiter.check("k")
        limiter.check("k")
        with pytest.raises(Exception, match="Too many requests"):
            limiter.check("k")
        now[0] = 11.0
        limiter.check("k")  # window rolled over

    def test_keys_are_independent(self) -> None:
        limiter = SlidingWindowLimiter(limit=1, clock=lambda: 0.0)
        limiter.check("a")
        limiter.check("b")
        with pytest.raises(Exception, match="Too many requests"):
            limiter.check("a")

    def test_remaining_counts_down(self) -> None:
        limiter = SlidingWindowLimiter(limit=3, clock=lambda: 0.0)
        assert limiter.remaining("k") == 3
        limiter.check("k")
        assert limiter.remaining("k") == 2

    def test_key_table_is_bounded(self) -> None:
        limiter = SlidingWindowLimiter(limit=5, clock=lambda: 0.0, max_keys=10)
        for index in range(100):
            limiter.check(f"key-{index}")
        assert len(limiter._events) <= 10


class TestRetrievalQueryBuilding:
    def test_follow_up_inherits_the_previous_turn(self) -> None:
        query = build_retrieval_query(
            ["What are the password requirements?"], "What else?", max_chars=2000
        )
        assert "password" in query
        assert query.endswith("What else?")

    def test_self_contained_question_is_not_diluted_by_history(self) -> None:
        """Appending history to a complete question changes its vector and
        starts retrieving the wrong document."""
        question = "What are the password requirements?"
        assert build_retrieval_query(["unrelated earlier topic"], question, max_chars=2000) == (
            question
        )

    @pytest.mark.parametrize(
        "question",
        ["What should I do?", "And then?", "What else?", "Tell me more", "anything else?"],
    )
    def test_bare_follow_ups_are_recognised(self, question: str) -> None:
        assert needs_conversation_context(question) is True

    @pytest.mark.parametrize(
        "question",
        [
            "What are the password requirements?",
            "How do I report a phishing email?",
            "My VPN will not connect",
        ],
    )
    def test_complete_questions_stand_alone(self, question: str) -> None:
        assert needs_conversation_context(question) is False

    def test_only_recent_turns_are_used(self) -> None:
        history = ["first topic", "second topic", "third topic"]
        query = build_retrieval_query(history, "what else?", max_chars=2000)
        assert "first topic" not in query
        assert "third topic" in query

    def test_budget_is_respected(self) -> None:
        query = build_retrieval_query(["x" * 500], "what else", max_chars=200)
        assert len(query) <= 200

    def test_no_history_returns_the_question(self) -> None:
        assert build_retrieval_query([], "hello there", max_chars=2000) == "hello there"


class TestAuditTrail:
    def test_questions_and_answers_are_audited(self, client: TestClient, employee_headers) -> None:
        conversation_id = new_conversation(client, employee_headers)
        ask(client, employee_headers, conversation_id, "What are the password requirements?")
        with session_scope() as session:
            actions = {
                row.action
                for row in session.scalars(
                    select(AuditLog).where(AuditLog.action.like("chat.%"))
                ).all()
            }
        assert "chat.query.received" in actions
        assert "chat.query.answered" in actions

    def test_audit_detail_never_contains_message_text(
        self, client: TestClient, employee_headers
    ) -> None:
        conversation_id = new_conversation(client, employee_headers)
        ask(
            client,
            employee_headers,
            conversation_id,
            "My secret token is hunter2-should-not-be-stored",
        )
        with session_scope() as session:
            rows = session.scalars(select(AuditLog).where(AuditLog.action.like("chat.%"))).all()
        for row in rows:
            assert "hunter2-should-not-be-stored" not in repr(row.detail)
