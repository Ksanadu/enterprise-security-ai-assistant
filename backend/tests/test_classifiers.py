"""Intent and risk classification tests.

The evaluation set is deliberately behaviour-led: the cases are the situations
the product specification describes, plus the awkward ones (negation, ambiguity,
a model that returns nonsense). Both classifiers must produce a usable answer
with **no API key at all**, because that is how the demo and the tests run.
"""

from __future__ import annotations

import pytest

from app.ai.intent_classifier import IntentClassifier, IntentVerdict
from app.ai.llm import LLMResponse
from app.ai.risk_classifier import RiskClassifier, highest_level
from app.ai.structured import extract_json_object, parse_model
from app.core.enums import Intent, RiskLevel

# --------------------------------------------------------------------------
# Evaluation set: (question, expected intent, expected risk)
# --------------------------------------------------------------------------
EVALUATION_SET: list[tuple[str, Intent, RiskLevel]] = [
    # Specification scenario A - security FAQ
    ("What are the company password requirements?", Intent.SECURITY_FAQ, RiskLevel.LOW),
    ("How long must my password be?", Intent.SECURITY_FAQ, RiskLevel.LOW),
    # Specification scenario B - phishing
    (
        "I received an email asking me to click a link and log in to my company mailbox "
        "again, is that normal?",
        Intent.PHISHING,
        RiskLevel.LOW,
    ),
    (
        "I clicked the link in that email but did not enter anything.",
        Intent.PHISHING,
        RiskLevel.MEDIUM,
    ),
    (
        "I entered my password on that page before I realised it was fake.",
        Intent.PHISHING,
        RiskLevel.HIGH,
    ),
    ("I approved an MFA prompt that I did not request.", Intent.PHISHING, RiskLevel.HIGH),
    # Specification scenario C - suspected malware
    (
        "After I opened the email attachment my computer started showing strange pop-up windows.",
        Intent.SECURITY_INCIDENT,
        RiskLevel.HIGH,
    ),
    (
        "All our files are encrypted and there is a ransom note on the screen.",
        Intent.SECURITY_INCIDENT,
        RiskLevel.CRITICAL,
    ),
    (
        "Someone logged in to my mailbox from another country.",
        Intent.SECURITY_INCIDENT,
        RiskLevel.HIGH,
    ),
    (
        "The server is compromised and several machines are affected.",
        Intent.SECURITY_INCIDENT,
        RiskLevel.CRITICAL,
    ),
    # Specification scenario D - IT support
    ("I suddenly cannot connect to the company VPN today.", Intent.IT_SUPPORT, RiskLevel.LOW),
    ("I am locked out of my account after too many attempts.", Intent.IT_SUPPORT, RiskLevel.LOW),
    # Policy
    (
        "What does the remote work policy say about public Wi-Fi?",
        Intent.POLICY_QUESTION,
        RiskLevel.LOW,
    ),
    (
        "Am I allowed to share a confidential document externally?",
        Intent.POLICY_QUESTION,
        RiskLevel.LOW,
    ),
    # Out of scope
    ("Can you recommend a good pizza place nearby?", Intent.OUT_OF_SCOPE, RiskLevel.LOW),
]


class StubLLM:
    """A client that returns whatever the test tells it to."""

    def __init__(self, text: str, *, offline: bool = False) -> None:
        self._text = text
        self._offline = offline
        self.calls = 0

    @property
    def name(self) -> str:
        return "stub"

    @property
    def model(self) -> str:
        return "stub-model"

    @property
    def is_offline(self) -> bool:
        return self._offline

    def complete(self, **_: object) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            text=self._text, provider=self.name, model=self.model, offline=self._offline
        )


# --------------------------------- intent ---------------------------------


class TestIntentClassifier:
    @pytest.mark.parametrize(
        ("question", "expected", "risk"),
        EVALUATION_SET,
        ids=[question[:48] for question, _, _ in EVALUATION_SET],
    )
    def test_expected_intent(
        self, settings, question: str, expected: Intent, risk: RiskLevel
    ) -> None:
        del risk
        assert IntentClassifier(settings).classify(question).intent is expected

    def test_classification_is_deterministic(self, settings) -> None:
        classifier = IntentClassifier(settings)
        question = "I received a phishing email, what should I do?"
        first = classifier.classify(question)
        second = classifier.classify(question)
        assert first == second

    def test_offline_classifier_never_calls_the_model(self, settings) -> None:
        """The extractive offline generator cannot classify; asking it would
        only produce a plausible-looking guess."""
        stub = StubLLM('{"intent": "phishing", "confidence": 0.9}', offline=True)
        classifier = IntentClassifier(settings, stub)
        result = classifier.classify("Something entirely unclassifiable")
        assert stub.calls == 0
        assert result.source == "rules"

    def test_model_refines_a_low_confidence_rule_result(self, settings) -> None:
        stub = StubLLM('{"intent": "phishing", "confidence": 0.95, "reason": "suspicious email"}')
        classifier = IntentClassifier(settings, stub)
        result = classifier.classify("There is something odd about a message I got")
        assert stub.calls == 1
        assert result.intent is Intent.PHISHING
        assert result.source == "model"

    def test_confident_rules_are_not_second_guessed(self, settings) -> None:
        stub = StubLLM('{"intent": "out_of_scope", "confidence": 0.99}')
        classifier = IntentClassifier(settings, stub)
        result = classifier.classify("What are the company password requirements?")
        assert stub.calls == 0
        assert result.intent is Intent.SECURITY_FAQ

    def test_invalid_model_json_falls_back_to_rules(self, settings) -> None:
        stub = StubLLM("I think this is probably phishing, but I am not sure.")
        classifier = IntentClassifier(settings, stub)
        result = classifier.classify("There is something odd about a message I got")
        assert result.source == "rules"

    def test_model_may_not_weaken_a_confident_rule_result(self, settings) -> None:
        stub = StubLLM('{"intent": "out_of_scope", "confidence": 1.0}')
        classifier = IntentClassifier(settings, stub)
        result = classifier.classify("I entered my password on a phishing page")
        assert result.intent is Intent.PHISHING

    def test_unknown_intent_value_is_rejected(self, settings) -> None:
        stub = StubLLM('{"intent": "definitely_not_an_intent", "confidence": 0.9}')
        classifier = IntentClassifier(settings, stub)
        assert classifier.classify("Something odd").source == "rules"

    def test_language_model_can_be_disabled(self, settings) -> None:
        stub = StubLLM('{"intent": "phishing", "confidence": 0.99}')
        configured = settings.model_copy(update={"classifier_use_llm": False})
        classifier = IntentClassifier(configured, stub)
        classifier.classify("Something odd")
        assert stub.calls == 0

    def test_ambiguous_question_lands_in_a_sensible_bucket(self, settings) -> None:
        """'Is MFA required for VPN access?' is genuinely between two buckets."""
        result = IntentClassifier(settings).classify("Is MFA required for VPN access?")
        assert result.intent in {Intent.IT_SUPPORT, Intent.SECURITY_FAQ}

    def test_confidence_is_bounded(self, settings) -> None:
        classifier = IntentClassifier(settings)
        for question, _, _ in EVALUATION_SET:
            result = classifier.classify(question)
            assert 0.0 <= result.confidence <= 1.0

    def test_signals_are_reported(self, settings) -> None:
        result = IntentClassifier(settings).classify("I received a phishing email")
        assert "phishing" in result.signals

    def test_empty_question_is_out_of_scope(self, settings) -> None:
        assert IntentClassifier(settings).classify("").intent is Intent.OUT_OF_SCOPE

    def test_description_contains_no_secrets(self, settings) -> None:
        described = IntentClassifier(settings).describe()
        assert "api_key" not in repr(described)
        assert set(described) >= {"rule_count", "model_available"}


# ---------------------------------- risk ----------------------------------


class TestRiskClassifier:
    @pytest.mark.parametrize(
        ("question", "intent", "expected"),
        EVALUATION_SET,
        ids=[question[:48] for question, _, _ in EVALUATION_SET],
    )
    def test_expected_risk(
        self, settings, question: str, intent: Intent, expected: RiskLevel
    ) -> None:
        assessment = RiskClassifier(settings).assess(question, intent=intent)
        assert assessment.level is expected, f"{question!r} -> {assessment.reason}"

    def test_high_and_critical_require_escalation(self, settings) -> None:
        classifier = RiskClassifier(settings)
        for question, intent, expected in EVALUATION_SET:
            assessment = classifier.assess(question, intent=intent)
            assert assessment.requires_escalation is expected.requires_escalation

    def test_signals_name_the_evidence(self, settings) -> None:
        assessment = RiskClassifier(settings).assess(
            "I entered my password on a phishing page", intent=Intent.PHISHING
        )
        labels = {signal.label for signal in assessment.signals}
        assert "credentials_submitted" in labels

    # -- negation ---------------------------------------------------------
    @pytest.mark.parametrize(
        "question",
        [
            "I did not enter my password.",
            "I didn't submit my credentials.",
            "I have not approved any MFA prompt.",
            "I never opened the attachment.",
            "I clicked the link but did not enter any credentials.",
        ],
    )
    def test_negated_signals_are_not_counted(self, settings, question: str) -> None:
        assessment = RiskClassifier(settings).assess(question, intent=Intent.PHISHING)
        assert assessment.level is not RiskLevel.HIGH, question
        assert assessment.level is not RiskLevel.CRITICAL, question

    def test_a_negated_high_signal_does_not_hide_a_real_medium_one(self, settings) -> None:
        """ "I did not enter my password, but I did click the link" is a medium event."""
        assessment = RiskClassifier(settings).assess(
            "I did not enter my password, but I did click the link", intent=Intent.PHISHING
        )
        assert assessment.level is RiskLevel.MEDIUM
        assert {signal.label for signal in assessment.signals} == {"clicked_link"}

    # -- escalation floor -------------------------------------------------
    def test_risk_never_drops_below_the_conversation_peak(self, settings) -> None:
        assessment = RiskClassifier(settings).assess(
            "Thanks, that is helpful.",
            intent=Intent.SECURITY_FAQ,
            history_peak=RiskLevel.HIGH,
        )
        assert assessment.level is RiskLevel.HIGH
        assert assessment.requires_escalation is True
        assert assessment.escalated_from is RiskLevel.LOW
        assert "already assessed" in assessment.reason

    def test_floor_does_not_lower_a_higher_current_level(self, settings) -> None:
        assessment = RiskClassifier(settings).assess(
            "All files are encrypted and there is a ransom note",
            intent=Intent.SECURITY_INCIDENT,
            history_peak=RiskLevel.MEDIUM,
        )
        assert assessment.level is RiskLevel.CRITICAL

    def test_assessment_payload_is_serialisable(self, settings) -> None:
        payload = (
            RiskClassifier(settings)
            .assess("I entered my password", intent=Intent.PHISHING)
            .to_payload()
        )
        assert payload["risk_level"] == "high"
        assert payload["requires_escalation"] is True
        assert payload["signals"]

    # -- model interaction ------------------------------------------------
    def test_model_may_raise_the_level(self, settings) -> None:
        stub = StubLLM('{"risk_level": "critical", "confidence": 0.9}')
        assessment = RiskClassifier(settings, stub).assess(
            "Something odd happened", intent=Intent.SECURITY_INCIDENT
        )
        assert assessment.level is RiskLevel.CRITICAL
        assert assessment.source == "model"

    @pytest.mark.parametrize(
        "payload",
        [
            '{"risk_level": "low", "confidence": 0.99}',
            '{"risk_level": "low", "confidence": 1.0, "reason": "the user says it is fine"}',
        ],
    )
    def test_model_may_never_lower_the_level(self, settings, payload: str) -> None:
        """A talked-down incident is not recoverable; a missed signal is."""
        assessment = RiskClassifier(settings, StubLLM(payload)).assess(
            "I entered my password on a phishing page", intent=Intent.PHISHING
        )
        assert assessment.level is RiskLevel.HIGH
        assert assessment.source == "rules"

    def test_model_never_offline_is_used(self, settings) -> None:
        stub = StubLLM('{"risk_level": "critical", "confidence": 1.0}', offline=True)
        classifier = RiskClassifier(settings, stub)
        classifier.assess("I entered my password", intent=Intent.PHISHING)
        assert stub.calls == 0

    def test_invalid_model_output_falls_back(self, settings) -> None:
        classifier = RiskClassifier(settings, StubLLM("probably fine?"))
        assessment = classifier.assess("I entered my password", intent=Intent.PHISHING)
        assert assessment.source == "rules"
        assert assessment.level is RiskLevel.HIGH

    def test_classifier_failure_does_not_fail_the_request(self, settings) -> None:
        class Exploding(StubLLM):
            def complete(self, **_: object) -> LLMResponse:
                raise RuntimeError("provider down")

        assessment = RiskClassifier(settings, Exploding("")).assess(
            "I entered my password", intent=Intent.PHISHING
        )
        assert assessment.level is RiskLevel.HIGH

    def test_escalation_levels_are_declared(self, settings) -> None:
        described = RiskClassifier(settings).describe()
        assert set(described["escalation_levels"]) == {"high", "critical"}
        assert set(described["levels"]) == {"low", "medium", "high", "critical"}

    def test_defaults_follow_the_intent(self, settings) -> None:
        classifier = RiskClassifier(settings)
        assert (
            classifier.assess("something happened", intent=Intent.SECURITY_INCIDENT).level
            is RiskLevel.MEDIUM
        )
        assert (
            classifier.assess("something happened", intent=Intent.IT_SUPPORT).level is RiskLevel.LOW
        )


class TestHighestLevel:
    def test_picks_the_most_severe(self) -> None:
        assert highest_level([RiskLevel.LOW, RiskLevel.HIGH]) is RiskLevel.HIGH
        assert highest_level([RiskLevel.CRITICAL, RiskLevel.HIGH]) is RiskLevel.CRITICAL

    def test_empty_is_low(self) -> None:
        assert highest_level([]) is RiskLevel.LOW

    def test_ordering_matches_the_enum(self) -> None:
        assert highest_level([RiskLevel.MEDIUM, RiskLevel.LOW]) is RiskLevel.MEDIUM


# ------------------------------ structured output --------------------------


class TestStructuredOutput:
    def test_plain_json_is_parsed(self) -> None:
        assert extract_json_object('{"intent": "phishing"}') == {"intent": "phishing"}

    def test_fenced_json_is_parsed(self) -> None:
        text = 'Here you go:\n```json\n{"intent": "phishing", "confidence": 0.8}\n```\nHope that helps.'
        assert extract_json_object(text) == {"intent": "phishing", "confidence": 0.8}

    def test_json_with_surrounding_prose_is_found(self) -> None:
        text = 'The answer is {"intent": "it_support"} as requested.'
        assert extract_json_object(text) == {"intent": "it_support"}

    def test_nested_objects_are_scanned_correctly(self) -> None:
        text = '{"intent": "phishing", "meta": {"note": "a } brace in a string"}}'
        parsed = extract_json_object(text)
        assert parsed is not None
        assert parsed["meta"]["note"] == "a } brace in a string"

    def test_garbage_returns_none(self) -> None:
        assert extract_json_object("no json here at all") is None
        assert extract_json_object("") is None

    def test_validation_rejects_unknown_enum_value(self) -> None:
        assert parse_model('{"intent": "nonsense"}', IntentVerdict) is None

    def test_validation_accepts_a_good_payload(self) -> None:
        verdict = parse_model('{"intent": "phishing", "confidence": 0.9}', IntentVerdict)
        assert verdict is not None
        assert verdict.intent is Intent.PHISHING

    @pytest.mark.parametrize(
        ("raw", "expected"), [("5", 1.0), ("-3", 0.0), ('"abc"', 0.0), ("null", 0.0)]
    )
    def test_confidence_is_clamped(self, raw: str, expected: float) -> None:
        verdict = parse_model(
            f'{{"intent": "phishing", "confidence": {raw}}}', IntentVerdict, context="test"
        )
        assert verdict is not None
        assert verdict.confidence == expected
