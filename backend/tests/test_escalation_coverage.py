"""Escalation coverage: the events KB-009 says must reach a human, do.

This is the most important safety property in the product. The assistant's whole
purpose is to route a security incident to a person, so a *missed* escalation is
the failure that matters - not a noisy false alarm.

A QA pass measured it and the result was bad. Of 32 realistic phrasings of events
the published severity standard rates S1 or S2, **only 14 escalated (44%)**. The
root cause was vocabulary: the rules matched the policy's own words ("ransomware",
"data exfiltrated") while people describe the *effect* - "my files have been locked
and they want money", "customer data has been copied out to an external site".
Worse, 13 of the 18 misses were classified `out_of_scope`, which also skips
retrieval, so a ransomware report was answered with "I do not have an approved
knowledge document for this question" and nothing was filed at all.

The rules were extended to match the events in KB-009 section 2 rather than the
labels, and the coverage is now 32/32. Both halves are asserted here, because a
rule set that escalates everything would score 100% on the first half alone and be
useless.

Every phrasing below is grounded in a row of KB-009's severity table, quoted
alongside the corpus.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.ai.intent_classifier import IntentClassifier
from app.ai.risk_classifier import RiskClassifier
from app.core.config import get_settings
from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.evaluation]

def _sign_in(client: TestClient, role: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": DEMO_ACCOUNTS[role], "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}

#: KB-009 section 2 rows that require human escalation (S1 and S2), each with
#: realistic ways a person describes the event rather than naming it.
MUST_ESCALATE: dict[str, tuple[str, list[str]]] = {
    # "User entered credentials into a phishing page" -> S2
    "credentials entered into a phishing page": (
        "S2",
        [
            "I entered my password into the page it linked to.",
            "I did enter my password on that site.",
            "I typed my credentials into the fake login form.",
            "I put my username and password in before I realised.",
            "I gave them my login details.",
            "I logged in through that link with my company account.",
            "My password was entered on that page, unfortunately.",
            "I filled in the login form on the fake site.",
            "I submitted my password to it.",
            "I signed in using the link in the email.",
        ],
    ),
    # "User approved an unexpected MFA prompt" -> S2
    "unexpected MFA prompt approved": (
        "S2",
        [
            "I approved a login prompt I did not expect.",
            "I accepted an MFA push notification that was not mine.",
            "I confirmed a sign-in request I had not started.",
            "My phone showed a login approval and I tapped yes.",
            "I approved the authenticator prompt without thinking.",
        ],
    ),
    # "Malicious attachment executed on one endpoint" -> S2
    "malicious attachment executed": (
        "S2",
        [
            "I opened the attachment and something installed itself.",
            "I ran the file from the email and the machine is behaving oddly.",
            "The attachment executed and now there is a strange process running.",
            "I double-clicked the invoice and my screen flickered then a program started.",
            "A macro ran when I opened the document.",
        ],
    ),
    # "Ransomware or confirmed data exfiltration" -> S1
    "ransomware or exfiltration": (
        "S1",
        [
            "All my files are encrypted and there is a ransom note.",
            "My files have been locked and they want money.",
            "There is a note demanding payment and my documents will not open.",
            "Customer data has been copied out to an external site.",
            "A large amount of company data was uploaded to a personal cloud drive.",
        ],
    ),
    # "Privileged account suspected compromised" -> S1
    "privileged account compromised": (
        "S1",
        [
            "The domain administrator account may be compromised.",
            "Someone else appears to be using the service account.",
            "The root account credentials may have leaked.",
            "Our privileged admin login was used from an unknown location.",
        ],
    ),
    # "Lost device, unencrypted, or wipe unconfirmed" -> S1
    "lost device at risk": (
        "S1",
        [
            "I lost my unencrypted laptop with company data on it.",
            "My phone was stolen and it is not encrypted.",
            "The laptop was taken and the remote wipe did not confirm.",
        ],
    ),
}

#: Questions that must NOT escalate. The rules were widened to catch the corpus
#: above, and widening rules is how a classifier becomes trigger-happy - so the
#: restraint is asserted with the same care as the coverage.
MUST_NOT_ESCALATE = [
    # KB-009: "User reports a suspicious email without interacting" -> S4
    "I received an email asking me to click a link and log in again, is that normal?",
    "Someone sent me an email that looks like it is from IT. Should I be worried?",
    # KB-009: "Lost device, encrypted, remote wipe succeeded" -> S4
    "I lost my encrypted laptop but the remote wipe succeeded.",
    "My phone was stolen but it was encrypted and I wiped it remotely.",
    # Ordinary questions that merely mention the vocabulary.
    "What are the password requirements?",
    "How long must my password be?",
    "What is the policy on encrypting USB drives?",
    "How do I report a phishing email?",
    "Is there a template for reporting a suspicious message?",
    "What is the malware response procedure?",
    "How do I check whether my laptop is encrypted?",
    "Where do I find the incident severity classifications?",
    "Who do I contact out of hours?",
    "How do I request a new laptop?",
    "My laptop will not boot after the update last night.",
    "I cannot connect to the VPN today.",
    "Can I use a personal device for work?",
    "What should I do if I receive a suspicious attachment?",
    "Does the company encrypt backups?",
    "How are privileged accounts approved?",
]


@pytest.fixture(scope="module")
def classifiers() -> tuple[RiskClassifier, IntentClassifier]:
    settings = get_settings()
    return RiskClassifier(settings), IntentClassifier(settings)


class TestEventsThatMustReachAHuman:
    def test_the_corpus_matches_the_policy(self) -> None:
        # Every bucket names the KB-009 severity row it comes from, and every row
        # is one the policy says requires a human.
        assert len(MUST_ESCALATE) == 6
        for description, (severity, phrases) in MUST_ESCALATE.items():
            assert severity in {"S1", "S2"}, description
            assert len(phrases) >= 3, description

    @pytest.mark.parametrize("bucket", sorted(MUST_ESCALATE))
    def test_every_phrasing_escalates(
        self, classifiers: tuple[RiskClassifier, IntentClassifier], bucket: str
    ) -> None:
        risk_classifier, intent_classifier = classifiers
        _severity, phrases = MUST_ESCALATE[bucket]

        missed = []
        for phrase in phrases:
            intent = intent_classifier.classify(phrase).intent
            assessment = risk_classifier.assess(phrase, intent=intent)
            if not assessment.requires_escalation:
                missed.append((assessment.level.value, intent.value, phrase))

        assert not missed, f"{bucket}: {len(missed)} phrasing(s) would not reach a human:\n" + "\n".join(
            f"  risk={level} intent={intent}  {phrase}" for level, intent, phrase in missed
        )

    def test_the_whole_corpus_escalates(self, classifiers: tuple[RiskClassifier, IntentClassifier]) -> None:
        risk_classifier, intent_classifier = classifiers
        phrases = [p for _severity, phrases in MUST_ESCALATE.values() for p in phrases]
        escalated = 0
        for phrase in phrases:
            intent = intent_classifier.classify(phrase).intent
            if risk_classifier.assess(phrase, intent=intent).requires_escalation:
                escalated += 1
        # Stated as a ratio so the number is visible in the report. It was 44%
        # before the rules were extended.
        assert escalated == len(phrases), f"{escalated}/{len(phrases)} escalate"

    def test_no_event_is_silently_out_of_scope(
        self, classifiers: tuple[RiskClassifier, IntentClassifier]
    ) -> None:
        """A described security event must not be answered as "I do not cover that".

        `out_of_scope` skips retrieval entirely (a deliberate Phase 2 decision),
        so an event misfiled there gets no document, no citation and no
        escalation. That is how a ransomware report was answered with "I do not
        have an approved knowledge document for this question".
        """
        risk_classifier, intent_classifier = classifiers
        phrases = [p for _severity, phrases in MUST_ESCALATE.values() for p in phrases]

        wrong = [
            (intent_classifier.classify(phrase).intent.value, phrase)
            for phrase in phrases
            if intent_classifier.classify(phrase).intent.value == "out_of_scope"
        ]
        assert not wrong, f"events classified out of scope: {wrong}"

    def test_a_critical_event_is_not_merely_high(
        self, classifiers: tuple[RiskClassifier, IntentClassifier]
    ) -> None:
        # The distinction is not cosmetic: KB-009 gives S1 a 15-minute response
        # target and S2 four business hours.
        risk_classifier, intent_classifier = classifiers
        for bucket in ("ransomware or exfiltration", "privileged account compromised"):
            _severity, phrases = MUST_ESCALATE[bucket]
            for phrase in phrases:
                intent = intent_classifier.classify(phrase).intent
                assessment = risk_classifier.assess(phrase, intent=intent)
                assert assessment.level.value == "critical", (bucket, phrase, assessment.level.value)


class TestTheAnswerAgreesWithItsPayload:
    """An answer must not contradict the citations beside it.

    Found while measuring the corpus above. For "My files have been locked and
    they want money" retrieval succeeded - two authorised documents, `grounded`
    true - but the offline extractive provider declined to quote any sentence
    (correctly: none of them answered the question), and the empty answer was
    replaced with the *no-context* text. The user was told "I do not have an
    approved knowledge document that answers this question" while the same
    response listed two of them and raised a ticket.
    """

    @pytest.mark.parametrize(
        "question",
        [
            "My files have been locked and they want money.",
            "Customer data has been copied out to an external site.",
            "What are the company password requirements?",
            "I suddenly cannot connect to the company VPN today.",
        ],
    )
    def test_the_text_matches_the_citations(self, question: str) -> None:
        from app.ai.response_generator import ResponseGenerator
        from app.core.enums import Role
        from app.services.knowledge_service import KnowledgeService

        settings = get_settings()
        knowledge = KnowledgeService(settings)
        knowledge.startup()

        retrieval = knowledge.search(question, role=Role.EMPLOYEE)
        answer = ResponseGenerator(settings).generate(
            question=question, role=Role.EMPLOYEE, retrieval=retrieval
        )

        claims_nothing_exists = "i do not have an approved knowledge document" in answer.answer.lower()
        assert not (claims_nothing_exists and answer.source_documents), (
            f"{question!r}: the answer says no document exists while citing "
            f"{[d['document_id'] for d in answer.source_documents]}"
        )

    def test_an_ungrounded_answer_does_claim_nothing_exists(self, client: TestClient) -> None:
        # The other side of the same invariant: with no matches, saying so is
        # exactly right - and it must not hint that other documents exist.
        #
        # This has to go through the pipeline, not `search`: skipping retrieval for
        # an out-of-scope question is a `chat_service` decision, and calling the
        # knowledge service directly would retrieve regardless.
        headers = _sign_in(client, "employee")
        conversation_id = int(
            client.post("/api/v1/chat/conversations", headers=headers, json={}).json()["id"]
        )
        payload = client.post(
            f"/api/v1/chat/conversations/{conversation_id}/messages",
            headers=headers,
            json={"content": "Please explain the offside rule in football."},
        ).json()["assistant_message"]["payload"]

        assert payload["grounded"] is False
        assert payload["source_documents"] == []
        assert "i do not have an approved knowledge document" in payload["answer"].lower()
        # It must not leak the existence of restricted material.
        assert "restricted" not in payload["answer"].lower()


class TestQuestionsThatMustNotEscalate:

    @pytest.mark.parametrize("question", MUST_NOT_ESCALATE)
    def test_it_does_not_escalate(
        self, classifiers: tuple[RiskClassifier, IntentClassifier], question: str
    ) -> None:
        risk_classifier, intent_classifier = classifiers
        intent = intent_classifier.classify(question).intent
        assessment = risk_classifier.assess(question, intent=intent)
        assert not assessment.requires_escalation, (
            f"false alarm on {question!r}: risk={assessment.level.value} "
            f"signals={[signal.label for signal in assessment.signals]}"
        )

    def test_the_false_alarm_rate_is_zero_across_the_corpus(
        self, classifiers: tuple[RiskClassifier, IntentClassifier]
    ) -> None:
        risk_classifier, intent_classifier = classifiers
        alarms = []
        for question in MUST_NOT_ESCALATE:
            intent = intent_classifier.classify(question).intent
            assessment = risk_classifier.assess(question, intent=intent)
            if assessment.requires_escalation:
                alarms.append((question, assessment.level.value))
        assert not alarms, f"{len(alarms)} false alarm(s): {alarms}"

    def test_the_evaluation_set_agrees(self, classifiers: tuple[RiskClassifier, IntentClassifier]) -> None:
        # The evaluation set already asserts this end to end; this is the same
        # property at the classifier level, so a rule change fails here first and
        # with a clearer message.
        import json
        from pathlib import Path

        path = Path(__file__).parent / "data" / "evaluation_questions.json"
        entries = json.loads(path.read_text(encoding="utf-8"))["questions"]
        risk_classifier, intent_classifier = classifiers

        disagreements = []
        for entry in entries:
            expected = entry["expected"]
            question = entry["question"]
            intent = intent_classifier.classify(question).intent
            assessment = risk_classifier.assess(question, intent=intent)
            if assessment.requires_escalation != expected["escalation"]:
                disagreements.append(
                    (entry["id"], question[:50], expected["escalation"], assessment.level.value)
                )
        assert not disagreements, disagreements
