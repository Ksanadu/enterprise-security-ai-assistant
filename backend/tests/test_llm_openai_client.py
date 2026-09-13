"""The real LLM client: the path the shipped configuration never executes.

`LLM_PROVIDER=mock` is the default, so `OpenAICompatibleLLMClient.complete` was
covered by nothing at all - 84% file coverage with the whole method missed. That
is the one code path whose failure would be invisible in every other test, since
every other test runs the offline generator.

The transport is stubbed, so these tests are deterministic and offline like the
rest of the suite, but they exercise the real request construction, the retry
loop, and the error contract. Claiming "a configurable LLM API" (PRODUCT_SPEC.md
section 6) is only honest if the configuration path is actually run.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.ai.llm import OpenAICompatibleLLMClient, get_llm_client
from app.core.errors import UpstreamServiceError


class _StubResponse:
    """The parts of ``httpx.Response`` the client touches."""

    def __init__(self, *, body: Any = None, status: int = 200, json_error: bool = False) -> None:
        self._body = body
        self.status_code = status
        self._json_error = json_error

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://llm.example/v1/chat/completions")
            raise httpx.HTTPStatusError(
                f"{self.status_code}", request=request, response=httpx.Response(self.status_code)
            )

    def json(self) -> Any:
        if self._json_error:
            raise ValueError("not json")
        return self._body


def _completion_response(text: str) -> _StubResponse:
    return _StubResponse(body={"choices": [{"message": {"content": text}}]})


class _Recorder:
    """A stub `httpx.post` that records every attempt."""

    def __init__(self, *outcomes: Any) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, **kwargs: Any) -> Any:
        self.calls.append({"url": url, **kwargs})
        outcome = self.outcomes.pop(0) if self.outcomes else self.outcomes_default
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    outcomes_default: Any = None


@pytest.fixture
def client() -> OpenAICompatibleLLMClient:
    return OpenAICompatibleLLMClient(
        api_key="test-key-not-real",
        base_url="https://llm.example/v1/",
        model="gpt-4o-mini",
        temperature=0.0,
        timeout_seconds=5,
        max_retries=2,
    )


def _call(client: OpenAICompatibleLLMClient) -> Any:
    return client.complete(
        system_prompt="You are a security assistant.",
        user_prompt="What are the password requirements?",
        context_block="KB-001: passwords are at least 14 characters.",
    )


class TestTheRequestItBuilds:
    def test_it_posts_to_the_chat_completions_path(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(_completion_response("Passwords must be at least 14 characters."))
        monkeypatch.setattr(httpx, "post", recorder)

        _call(client)

        assert recorder.calls[0]["url"] == "https://llm.example/v1/chat/completions"

    def test_it_sends_the_key_and_the_documented_payload(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(_completion_response("Answer."))
        monkeypatch.setattr(httpx, "post", recorder)

        _call(client)

        call = recorder.calls[0]
        assert call["headers"]["Authorization"] == "Bearer test-key-not-real"
        assert call["json"]["model"] == "gpt-4o-mini"
        assert call["json"]["temperature"] == 0.0
        assert call["json"]["max_tokens"] == 900
        assert call["timeout"] == 5

    def test_the_context_block_is_delimited_in_the_user_message(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The context has to be separable from the instruction, or a retrieved
        # document can be read as one (see the guard's context patterns).
        recorder = _Recorder(_completion_response("Answer."))
        monkeypatch.setattr(httpx, "post", recorder)

        _call(client)

        messages = recorder.calls[0]["json"]["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "You are a security assistant."
        assert messages[1]["role"] == "user"
        assert "<context>" in messages[1]["content"]
        assert "KB-001: passwords are at least 14 characters." in messages[1]["content"]

    def test_a_successful_completion_is_returned_as_an_llm_response(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(_completion_response("  Passwords must be at least 14 characters.  "))
        monkeypatch.setattr(httpx, "post", recorder)

        response = _call(client)

        assert response.text == "Passwords must be at least 14 characters."
        assert response.provider == "openai_compatible"
        assert response.model == "gpt-4o-mini"
        assert response.offline is False

    def test_the_client_describes_itself(
        self, client: OpenAICompatibleLLMClient
    ) -> None:
        assert client.name == "openai_compatible"
        assert client.model == "gpt-4o-mini"
        assert client.is_offline is False


class TestItsFailureContract:
    def test_a_transient_failure_is_retried_and_then_succeeds(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(httpx.ConnectError("connection refused"), _completion_response("Answer."))
        monkeypatch.setattr(httpx, "post", recorder)

        response = _call(client)

        assert response.text == "Answer."
        assert len(recorder.calls) == 2

    def test_it_gives_up_after_the_configured_attempts(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(*[httpx.ConnectError("refused")] * 5)
        monkeypatch.setattr(httpx, "post", recorder)

        with pytest.raises(UpstreamServiceError):
            _call(client)

        # One initial attempt plus `max_retries`.
        assert len(recorder.calls) == 3

    def test_an_http_error_status_is_retried(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(_StubResponse(status=503), _completion_response("Answer."))
        monkeypatch.setattr(httpx, "post", recorder)

        assert _call(client).text == "Answer."
        assert len(recorder.calls) == 2

    def test_a_body_that_is_not_json_is_retried_then_reported(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(_StubResponse(json_error=True))
        monkeypatch.setattr(httpx, "post", recorder)

        with pytest.raises(UpstreamServiceError):
            _call(client)

    def test_an_empty_completion_is_an_error_not_an_empty_answer(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(_completion_response("   "))
        monkeypatch.setattr(httpx, "post", recorder)

        with pytest.raises(UpstreamServiceError):
            _call(client)
        # An empty answer is a provider fault, not something to retry.
        assert len(recorder.calls) == 1

    def test_a_missing_choices_key_is_reported_not_leaked(
        self, client: OpenAICompatibleLLMClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder(_StubResponse(body={"error": {"message": "quota exceeded for key sk-x"}}))
        monkeypatch.setattr(httpx, "post", recorder)

        with pytest.raises(UpstreamServiceError) as raised:
            _call(client)

        # The provider's error text may echo request content or a key.
        assert "quota exceeded" not in str(raised.value)
        assert "sk-x" not in str(raised.value)

    def test_a_key_is_required(self) -> None:
        from app.core.errors import ConfigurationError

        with pytest.raises(ConfigurationError, match="LLM_API_KEY"):
            OpenAICompatibleLLMClient(api_key="", base_url="https://llm.example/v1", model="m")


class TestTheFactoryWiresItFromSettings:
    def test_it_builds_the_configured_client(self, settings: Any) -> None:
        configured = settings.model_copy(
            update={
                "llm_provider": "openai_compatible",
                "llm_api_key": "test-key-not-real",
                "llm_base_url": "https://llm.example/v1",
                "llm_model": "gpt-4o-mini",
            }
        )

        client = get_llm_client(configured)

        assert isinstance(client, OpenAICompatibleLLMClient)
        assert client.model == "gpt-4o-mini"
        assert client.is_offline is False

    def test_the_default_provider_stays_offline(self, settings: Any) -> None:
        # The shipped default is what the whole suite and the demo run on.
        assert settings.llm_provider == "mock"
        assert get_llm_client(settings).is_offline is True
