"""Credential redaction tests.

The heuristic has two failure modes and both matter: masking a normal question
makes the product look broken, and failing to mask a pasted password leaves a
credential on record in a ticket. The second is worse, so the tests below lean on
it - but the first has to hold too.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.security.redaction import redact_credentials

pytestmark = pytest.mark.security


class TestCredentialsAreMasked:
    @pytest.mark.parametrize(
        "text",
        [
            "I entered my password hunter2-should-not-be-stored on a fake page.",
            "My password is correcthorsebatterystaple and I typed it in.",
            "the token abc123def456 was used",
            "the api key sk-abcdef1234567890 leaked",
            "password: SuperSecret1!",
            "password=SuperSecret1!",
            'my passphrase "correct horse battery staple 9" was entered',
            "the one-time code 483920 was accepted",
            "otp 918273",
        ],
    )
    def test_secret_values_are_replaced(self, text: str) -> None:
        cleaned = redact_credentials(text)
        assert "***REDACTED***" in cleaned, text

    def test_a_pasted_credential_is_removed_from_the_sentence(self) -> None:
        cleaned = redact_credentials(
            "I entered my password hunter2-should-not-be-stored on a fake page."
        )
        assert "hunter2-should-not-be-stored" not in cleaned
        # The incident description survives; only the secret is gone.
        assert "I entered my password" in cleaned
        assert "on a fake page" in cleaned

    def test_sentence_punctuation_is_preserved(self) -> None:
        cleaned = redact_credentials("My password is correcthorsebatterystaple.")
        assert cleaned.endswith(".")
        assert "correcthorsebatterystaple" not in cleaned


class TestOrdinaryTextIsUntouched:
    @pytest.mark.parametrize(
        "text",
        [
            "What are the company password requirements?",
            "I forgot my password and cannot log in.",
            "I entered my password on a fake page.",
            "I need to know the password policy for the VPN.",
            "How long must my password be?",
            "Is MFA required for VPN access?",
            "Someone logged in to my mailbox from another country.",
            "After I opened the attachment my computer showed strange pop-ups.",
            "The password reset process is documented in KB-001.",
            "",
        ],
    )
    def test_nothing_is_masked(self, text: str) -> None:
        assert redact_credentials(text) == text

    def test_a_long_word_that_is_not_a_secret(self) -> None:
        # Long enough to look secret-shaped, but it is an English word.
        assert "authentication" in redact_credentials("The password authentication failed.")


class TestEmptyAndEdgeCases:
    def test_empty_string(self) -> None:
        assert redact_credentials("") == ""

    def test_none_like_input_is_handled(self) -> None:
        assert redact_credentials("") == ""

    def test_multiple_credentials_in_one_sentence(self) -> None:
        cleaned = redact_credentials("my password hunter2abc and my token xyz987654 were used")
        assert "hunter2abc" not in cleaned
        assert "xyz987654" not in cleaned
        assert cleaned.count("***REDACTED***") == 2


class TestNothingPersistedKeepsThePlaintext:
    """The redaction has to run at the storage boundary, not just for tickets.

    A user reporting an incident is *supposed* to say what they entered. The
    ticket body already masked it; the message row and the conversation title
    derived from it did not, which left the credential in the database and on the
    user's own screen.
    """

    CREDENTIAL = "Sup3rSecret!2024"
    REPORT = (
        "I entered my password Sup3rSecret!2024 on a page that turned out to be fake."
    )

    def _conversation_with_report(self, client: TestClient, headers: dict[str, str]) -> dict:
        conversation_id = int(
            client.post("/api/v1/chat/conversations", headers=headers, json={}).json()["id"]
        )
        response = client.post(
            f"/api/v1/chat/conversations/{conversation_id}/messages",
            headers=headers,
            json={"content": self.REPORT},
        )
        assert response.status_code == 200, response.text
        return response.json()

    def test_the_stored_message_is_masked(self, client: TestClient, login) -> None:
        body = self._conversation_with_report(client, login("employee"))
        stored = body["user_message"]["content"]
        assert self.CREDENTIAL not in stored
        assert "***REDACTED***" in stored
        # The sentence still reads as a sentence.
        assert "on a page that turned out to be fake" in stored

    def test_the_conversation_title_is_masked(self, client: TestClient, login) -> None:
        headers = login("employee")
        body = self._conversation_with_report(client, headers)
        detail = client.get(
            f"/api/v1/chat/conversations/{body['conversation_id']}", headers=headers
        ).json()
        assert self.CREDENTIAL not in detail["title"]
        assert "***REDACTED***" in detail["title"]

    def test_reloading_the_history_never_returns_the_credential(
        self, client: TestClient, login
    ) -> None:
        headers = login("employee")
        body = self._conversation_with_report(client, headers)
        detail = client.get(
            f"/api/v1/chat/conversations/{body['conversation_id']}", headers=headers
        )
        assert self.CREDENTIAL not in detail.text

    def test_the_ticket_body_is_masked_too(self, client: TestClient, login) -> None:
        headers = login("employee")
        body = self._conversation_with_report(client, headers)
        reference = body["assistant_message"]["payload"]["ticket_reference"]
        assert reference, "a submitted credential must escalate"
        ticket = client.get(f"/api/v1/tickets/{reference}", headers=headers)
        assert self.CREDENTIAL not in ticket.text

    def test_classification_still_uses_the_raw_text(self, client: TestClient, login) -> None:
        # The whole point of redacting *after* the pipeline: the wording is the
        # signal, so masking it before classification would lose the incident.
        body = self._conversation_with_report(client, login("employee"))
        payload = body["assistant_message"]["payload"]
        assert payload["intent"] == "phishing"
        assert payload["risk_level"] == "high"
        assert "credentials_submitted" in {
            signal["label"] for signal in payload["risk_signals"]
        }
        assert payload["human_escalation"] is True

    def test_an_ordinary_question_is_persisted_unchanged(self, client: TestClient, login) -> None:
        headers = login("employee")
        question = "What are the company's password requirements?"
        conversation_id = int(
            client.post("/api/v1/chat/conversations", headers=headers, json={}).json()["id"]
        )
        body = client.post(
            f"/api/v1/chat/conversations/{conversation_id}/messages",
            headers=headers,
            json={"content": question},
        ).json()
        assert body["user_message"]["content"] == question
