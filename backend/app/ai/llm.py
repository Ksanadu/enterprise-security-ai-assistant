"""LLM clients.

Two providers ship with the platform.

``mock`` (default, offline)
    A deterministic, extractive generator. It selects the sentences from the
    retrieved context that best match the question and assembles them into a
    grounded answer. It needs no API key and no network, so the entire pipeline -
    retrieval, permissions, citations, escalation - can be exercised and tested
    end to end. It is deliberately mechanical: it never invents content, so a
    citation from the mock provider is always traceable to a retrieved chunk.

``openai_compatible``
    Any OpenAI-compatible ``/chat/completions`` endpoint. Set ``LLM_PROVIDER``
    and ``LLM_API_KEY``; nothing else changes.

Both satisfy :class:`LLMClient`. Neither is ever asked to make an authorization
decision: the model only ever sees context that backend code has already
authorised.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.core.config import Settings, get_settings
from app.core.errors import ConfigurationError, UpstreamServiceError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """A model completion plus the usage metadata worth auditing."""

    text: str
    provider: str
    model: str
    #: True when the answer came from the deterministic offline generator.
    offline: bool = False


class LLMClient(Protocol):
    """Generates text from a system prompt and a user prompt."""

    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def is_offline(self) -> bool: ...

    def complete(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        context_block: str,
        max_tokens: int = 900,
    ) -> LLMResponse: ...


#: Framing notes at the top of every knowledge document. They are part of the
#: document, but quoting them as an *answer* produces nonsense such as
#: "system. Internal use only — restricted to the Security Team."
BOILERPLATE_PATTERNS = (
    "simulated content",
    "fictional sample documentation",
    "internal use only",
    "intended for it support",
    "intended for the it service desk",
    "intended for the security team",
    "all contact details below are fictional",
    "does not describe any real organisation",
)

#: A trailing conjunction, preposition or article means the line was cut. A
#: trailing comma is caught by the terminal-punctuation rule. Semicolons and
#: colons are NOT truncation markers: bullet lists legitimately end with them.
_FRAGMENT_TAIL = re.compile(
    r"\b(?:or|and|but|the|a|an|of|to|with|for|in|on|by|is|are|as|at|from|that|which)$", re.I
)
#: Characters a complete statement may end with.
_TERMINAL_CHARS = frozenset(".;:!?)]}\"'`")
_CONTINUATION_START = re.compile(r"^(?:and|or|but|which|that|then|also|including)\b", re.I)


def is_boilerplate(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in BOILERPLATE_PATTERNS)


def looks_truncated(text: str) -> bool:
    """True when a line was cut by a chunk boundary mid-phrase.

    Chunking splits on blank lines wherever it can, but a long bullet list still
    has to be divided. Quoting half a sentence is worse than quoting nothing, so
    the generator uses this to discard the fragments.
    """
    stripped = text.strip()
    if not stripped:
        return True
    if stripped.count("**") % 2 != 0:  # unbalanced emphasis
        return True
    if stripped.count("(") != stripped.count(")"):
        return True
    if _FRAGMENT_TAIL.search(stripped):
        return True
    # A statement that simply stops, without terminal punctuation, was cut.
    if stripped[-1] not in _TERMINAL_CHARS:
        return True

    # List items legitimately begin with a lower-case verb ("not contain the
    # username"), so the remaining checks only apply to prose.
    if stripped.startswith(("- ", "* ")) or re.match(r"^\d+[.)]\s", stripped):
        return False

    # Prose is expected to start with a capital. Lower case means the chunk
    # boundary cut into the middle of it - the source text
    # "Fictional sample documentation for a demonstration system." once surfaced
    # in an answer as "tion for a demonstration system.".
    if stripped[0].islower():
        return True
    return bool(_CONTINUATION_START.match(stripped))


def split_sentences(text: str) -> list[str]:
    """Split Markdown into quotable sentences and list items.

    Three details matter for answer quality:

    * Table rows and bare headings are dropped - they are structural fragments,
      and quoting them yields "| General security question | 1 business day |".
    * Consecutive prose lines are **joined before splitting**, because Markdown
      paragraphs are hard-wrapped: treating each line as a sentence produced
      fragments like "and hybrid working, including home offices, co-working".
    * Bullet and numbered items are kept whole, since procedures are written as
      steps.
    """
    sentences: list[str] = []
    for block in re.split(r"\n\s*\n", text):
        sentences.extend(_split_block(block))
    return sentences


def _split_block(block: str) -> list[str]:
    """Split one Markdown block, joining hard-wrapped paragraph lines first."""
    if not block.strip():
        return []

    sentences: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if not paragraph:
            return
        joined = " ".join(paragraph).strip()
        paragraph.clear()
        if not joined:
            return
        for piece in re.split(r"(?<=[.!?])\s+", joined):
            piece = piece.strip()
            if piece and not is_boilerplate(piece):
                sentences.append(piece)

    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line in {"---", "***", "___"}:
            flush_paragraph()
            continue
        if line.startswith("|") or re.match(r"^\|?[\s:|-]+\|", line):
            flush_paragraph()
            continue
        line = line.lstrip("> ").strip()
        if line.startswith("…"):
            line = line.lstrip("… ").strip()  # chunk-overlap marker
        if not line or is_boilerplate(line):
            flush_paragraph()
            continue
        if line.startswith(("- ", "* ")) or re.match(r"^\d+[.)]\s", line):
            flush_paragraph()
            sentences.append(line)
            continue
        paragraph.append(line)

    flush_paragraph()
    return sentences


def _clean(text: str) -> str:
    """Remove Markdown emphasis so the answer reads as plain prose."""
    text = re.sub(r"\*\*(?P<inner>[^*]+)\*\*", r"\g<inner>", text)
    text = re.sub(r"(?<!\*)\*(?!\*)(?P<inner>[^*]+)\*(?!\*)", r"\g<inner>", text)
    text = text.replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def _keywords(text: str) -> set[str]:
    """Content words used for relevance scoring by the offline generator."""
    words = re.findall(r"[a-z][a-z0-9]{2,}", text.lower())
    stop = {
        "the",
        "and",
        "for",
        "are",
        "was",
        "were",
        "with",
        "that",
        "this",
        "from",
        "have",
        "has",
        "had",
        "you",
        "your",
        "our",
        "can",
        "will",
        "would",
        "should",
        "what",
        "when",
        "where",
        "which",
        "how",
        "why",
        "who",
        "not",
        "but",
        "any",
        "all",
        "out",
        "get",
        "got",
        "may",
        "must",
        "about",
        "into",
        "they",
        "them",
        "their",
        "there",
        "then",
        "than",
        "been",
        "being",
        "does",
        "did",
        "doing",
        "如果",
        "怎么",
        "什么",
    }
    return {word for word in words if word not in stop}


class MockLLMClient:
    """Deterministic offline generator.

    It never produces text that is not derived from the supplied context: it
    ranks the context's sentences against the question and returns the best
    ones. That makes it a faithful stand-in for a grounded LLM - if the
    retrieval or the permission filter is wrong, the answer is visibly wrong too.
    """

    def __init__(self, model: str = "offline-extractive-v1") -> None:
        self._model = model

    @property
    def name(self) -> str:
        return "mock"

    @property
    def model(self) -> str:
        return self._model

    @property
    def is_offline(self) -> bool:
        return True

    def complete(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        context_block: str,
        max_tokens: int = 900,
    ) -> LLMResponse:
        # `system_prompt` and `max_tokens` are accepted for interface parity; the
        # offline generator works from the question and the context only.
        del system_prompt
        del max_tokens

        if not context_block.strip():
            return LLMResponse(text="", provider=self.name, model=self._model, offline=True)

        question_terms = _keywords(user_prompt)
        # (relevance, block index, sentence index, text) - block index is kept so
        # the answer can prefer the best-matching document rather than a scatter
        # of sentences from everywhere.
        scored: list[tuple[float, int, int, str]] = []
        per_block_sentences: dict[int, list[tuple[int, str]]] = {}
        for block_index, block in enumerate(context_block.split("\n[")):
            block = block if block_index == 0 else "[" + block
            body = re.sub(r"^\[\d+\][^\n]*\n", "", block).strip()
            for sentence_index, sentence in enumerate(split_sentences(body)):
                cleaned = _clean(sentence)
                # Skip fragments cut by a chunk boundary: quoting half a
                # sentence is worse than quoting nothing.
                if len(cleaned) < 25 or looks_truncated(cleaned):
                    continue
                per_block_sentences.setdefault(block_index, []).append((sentence_index, cleaned))
                terms = _keywords(cleaned)
                if not terms:
                    continue
                overlap = len(question_terms & terms)
                if overlap == 0:
                    continue
                # Normalise so a long paragraph cannot win on length alone.
                score = overlap / math.sqrt(len(terms))
                scored.append((score, block_index, sentence_index, cleaned))

        if not scored:
            return LLMResponse(text="", provider=self.name, model=self._model, offline=True)

        scored.sort(key=lambda item: (-item[0], item[1], item[2]))

        best_block = scored[0][1]
        chosen: list[tuple[int, int, str]] = []
        seen: set[str] = set()

        def take(block_index: int, sentence_index: int, text: str) -> None:
            key = text.lower()
            if key in seen:
                return
            seen.add(key)
            chosen.append((block_index, sentence_index, text))

        # Lead with the opening statements of the best-matching document. A
        # section retrieved as a whole is relevant as a whole, and its first
        # lines normally carry the key fact - keyword ranking alone would skip
        # "be at least 14 characters long" because none of the question's words
        # appear in it.
        for sentence_index, text in per_block_sentences.get(best_block, [])[:2]:
            take(best_block, sentence_index, text)

        # Then fill in the best-scoring sentences, capped per document so one
        # verbose document cannot crowd out the rest.
        per_block: dict[int, int] = {}
        for _, block_index, sentence_index, text in scored:
            if block_index > best_block + 2:
                continue
            cap = 4 if block_index == best_block else 1
            if per_block.get(block_index, 0) >= cap:
                continue
            before = len(chosen)
            take(block_index, sentence_index, text)
            if len(chosen) > before:
                per_block[block_index] = per_block.get(block_index, 0) + 1
            if len(chosen) >= 6:
                break

        # Restore reading order: by document, then by position within it.
        chosen.sort(key=lambda item: (item[0], item[1]))
        return LLMResponse(
            text="\n\n".join(text for _, _, text in chosen),
            provider=self.name,
            model=self._model,
            offline=True,
        )


class OpenAICompatibleLLMClient:
    """Chat completions from any OpenAI-compatible endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        temperature: float = 0.0,
        timeout_seconds: int = 45,
        max_retries: int = 2,
    ) -> None:
        if not api_key:
            raise ConfigurationError("LLM_API_KEY is required when LLM_PROVIDER=openai_compatible")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._temperature = temperature
        self._timeout = timeout_seconds
        self._max_retries = max(0, max_retries)

    @property
    def name(self) -> str:
        return "openai_compatible"

    @property
    def model(self) -> str:
        return self._model

    @property
    def is_offline(self) -> bool:
        return False

    def complete(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        context_block: str,
        max_tokens: int = 900,
    ) -> LLMResponse:
        import httpx

        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"{user_prompt}\n\n<context>\n{context_block}\n</context>",
            },
        ]
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": self._temperature,
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = httpx.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=self._timeout,
                )
                response.raise_for_status()
                body = response.json()
                content = body["choices"][0]["message"]["content"]
                if not isinstance(content, str) or not content.strip():
                    raise UpstreamServiceError("The model returned an empty response.")
                return LLMResponse(
                    text=content.strip(),
                    provider=self.name,
                    model=self._model,
                    offline=False,
                )
            except UpstreamServiceError:
                raise
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "llm_request_failed attempt=%d error=%s", attempt + 1, type(exc).__name__
                )

        # The provider's error text may echo request content; never surface it.
        raise UpstreamServiceError("The language model is unavailable.") from last_error


def get_llm_client(settings: Settings | None = None) -> LLMClient:
    """Build the configured LLM client."""
    settings = settings or get_settings()
    if settings.llm_provider == "openai_compatible":
        return OpenAICompatibleLLMClient(
            api_key=settings.llm_api_key,
            base_url=settings.llm_base_url,
            model=settings.llm_model,
            temperature=settings.llm_temperature,
            timeout_seconds=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_retries,
        )
    return MockLLMClient()


def summarise_for_audit(response: LLMResponse) -> dict[str, object]:
    """Metadata about a completion that is safe to write to the audit log."""
    return {
        "provider": response.provider,
        "model": response.model,
        "offline": response.offline,
        "answer_chars": len(response.text),
    }


def join_sentences(sentences: Sequence[str]) -> str:
    return " ".join(sentence.strip() for sentence in sentences if sentence.strip())
