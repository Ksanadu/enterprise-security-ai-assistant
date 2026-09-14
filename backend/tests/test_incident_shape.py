"""The incident-shape backstop, and the breach reports it exists for.

The classification rules are a finite list and a finite list cannot cover every way a
person describes a breach. Measured, eight reports in a row - data offered for sale on
the dark web, source code taken by an attacker, blackmail after a leak, a customer list
sold online, internal documents on a public forum, an ex-employee walking out with
client data, and two credential-harvesting attempts - produced **no answer source, no
ticket and no escalation**. The user was told "I do not have an approved knowledge
document that answers this question" and nobody was notified.

This file asserts both halves of the repair: the shape detector's precision (it must not
fire on questions about incidents, or on the lost-device case the policy calls S4), and
that the reports themselves are no longer silent end to end.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.ai.incident_shape import detect_incident_shape
from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.evaluation]

#: Reports that must be recognised as an incident *shape*: an incident noun paired with
#: a compromise verb, or an actor holding something they should not.
SHAPES = [
    "Our database is being sold on the dark web",
    "An attacker has our source code",
    "We are being blackmailed after a leak",
    "Someone is selling our customer list online",
    "Our internal documents appeared on a public forum",
    "A former employee walked out with our client data",
    "Someone exported our customer list",
    "The intern emailed payroll data to the wrong address",
    "I deleted the production database by mistake",
]

#: Questions and resolved situations that must NOT trigger the backstop. The first
#: group is the bare-noun trap the project has been bitten by before; the last two are
#: KB-009 S4, which says a lost device that was encrypted and remotely wiped needs no
#: tracking at all.
NOT_SHAPES = [
    "What is the malware response procedure?",
    "How do I report a phishing email?",
    "What are the password requirements?",
    "How do I request a new laptop?",
    "I cannot connect to the VPN today.",
    "What is the policy on encrypting USB drives?",
    "My laptop will not boot after the update last night.",
    "Can I use a personal device for work?",
    "How are privileged accounts approved?",
    "Please explain the offside rule in football.",
    "What does the password policy say about sharing credentials?",
    "I received a suspicious email asking me to log in again.",
    "I lost my encrypted laptop but the remote wipe succeeded.",
    "My phone was stolen but it was encrypted and I wiped it remotely.",
]

#: Reports that must reach the security team: KB-009 rates each of these S1 or S2.
MUST_REACH_A_HUMAN = [
    "Our database is being sold on the dark web",
    "An attacker has our source code",
    "We are being blackmailed after a leak",
    "Someone is selling our customer list online",
    "Our internal documents appeared on a public forum",
    "A former employee walked out with our client data",
    "I deleted the production database by mistake",
    "The intern emailed payroll data to the wrong address",
]

#: Reports that are a phishing *report* with no interaction described: KB-009 S4, so no
#: page for a human - but the Phishing Response SOP must be cited, because telling the
#: user "I have no document for this" while KB-002 sits in their scope is the defect.
MUST_BE_ANSWERED_WITH_THE_SOP = [
    "A supplier emailed me asking for our payment system credentials. Is this a scam?",
    "I got a message asking me to confirm my login details for the payroll portal.",
]


class TestTheShapeDetector:
    @pytest.mark.parametrize("text", SHAPES)
    def test_an_incident_shape_is_detected(self, text: str) -> None:
        assert detect_incident_shape(text) is not None, text

    @pytest.mark.parametrize("text", NOT_SHAPES)
    def test_a_question_or_a_resolved_case_is_not_a_shape(self, text: str) -> None:
        shape = detect_incident_shape(text)
        assert shape is None, f"false positive: {shape} for {text!r}"

    def test_the_corpora_are_not_empty(self) -> None:
        assert len(SHAPES) >= 9
        assert len(NOT_SHAPES) >= 12


class TestBreachReportsAreNeverSilent:
    """The invariant: a report shape can never end as an unanswered, unfiled turn."""

    @staticmethod
    def _ask(client: TestClient, question: str) -> dict:
        headers = {"Authorization": f"Bearer {client.post(
            '/api/v1/auth/login',
            json={'email': DEMO_ACCOUNTS['employee'], 'password': DEMO_PASSWORD},
        ).json()['access_token']}"}
        conversation = client.post(
            "/api/v1/chat/conversations", json={}, headers=headers
        ).json()
        return client.post(
            f"/api/v1/chat/conversations/{conversation['id']}/messages",
            json={"content": question},
            headers=headers,
        ).json()["assistant_message"]["payload"]

    @pytest.mark.parametrize("question", SHAPES)
    def test_it_is_never_answered_with_nothing_and_filed_nowhere(
        self, client: TestClient, question: str
    ) -> None:
        payload = self._ask(client, question)
        silent = (
            payload["risk_level"] == "low"
            and not payload["human_escalation"]
            and not payload["ticket_reference"]
            and not payload["source_documents"]
        )
        assert not silent, f"a breach report vanished: {question}"

    @pytest.mark.parametrize("question", MUST_REACH_A_HUMAN)
    def test_a_severe_report_reaches_a_human(self, client: TestClient, question: str) -> None:
        payload = self._ask(client, question)
        assert payload["human_escalation"] is True, (question, payload["risk_level"])
        assert payload["ticket_reference"], question
        assert payload["risk_level"] in {"high", "critical"}, question

    @pytest.mark.parametrize("question", MUST_BE_ANSWERED_WITH_THE_SOP)
    def test_a_credential_harvesting_report_cites_the_phishing_sop(
        self, client: TestClient, question: str
    ) -> None:
        payload = self._ask(client, question)
        documents = {doc["document_id"] for doc in payload["source_documents"]}
        assert payload["intent"] != "out_of_scope", question
        assert "KB-002" in documents, (
            f"{question}: the phishing response SOP is in the employee's scope and was "
            f"not cited; sources were {sorted(documents)}"
        )
