"""Response generation: grounded answer plus recommended actions.

This stage answers *what the documents say*. It deliberately does not classify
intent, assess risk, or decide whether to open a ticket - those are separate
components (Phase 5 and Phase 6) with their own tests, and none of them may
influence what the user is allowed to read.

The generator is given a :class:`RetrievalResult`, which by construction only
contains chunks the caller's role may read. It has no access to the index, so it
cannot widen that set.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from dataclasses import replace

from app.ai.llm import (
    LLMClient,
    LLMResponse,
    MockLLMClient,
    get_llm_client,
    looks_truncated,
    split_sentences,
)
from app.ai.prompt_guard import GuardFinding, PromptGuard
from app.ai.prompts import (
    SYSTEM_PROMPT,
    build_no_context_answer,
    build_unextractable_answer,
    build_user_prompt,
)
from app.core.config import Settings, get_settings
from app.core.enums import Role
from app.rag.retriever import RetrievalResult

logger = logging.getLogger(__name__)

#: Lines that read like an instruction to the reader.
ACTION_PATTERNS = (
    re.compile(r"^(?:[-*]\s+|\d+[.)]\s+)(?P<action>.+)$"),
    re.compile(r"^(?:you\s+)?(?:must|should|always)\s+(?P<action>.+)$", re.I),
)

#: Openings that make a line a *prohibition*. Measured, these were being turned into
#: recommendations: the old pattern stripped the leading "never"/"do not" and kept the
#: verb, so "Never approve an MFA prompt you did not initiate" became "Approve an MFA
#: prompt", and the policy's "Do not:" list became advice to write passwords on paper.
NEGATIVE_OPENING = re.compile(
    r"^(?:you\s+)?(?:must\s+not|should\s+not|shall\s+not|never|do\s+not|don'?t|avoid|"
    r"not\s+be|prohibited|forbidden|disallowed|refrain\s+from)\b",
    re.IGNORECASE,
)

#: An introduction that puts everything after it in the negative: "Passwords must not
#: be:", "Do not:". Bullets under one of these are prohibitions even though the bullet
#: itself contains no negative word.
NEGATIVE_INTRO = re.compile(
    r"(?:must\s+not|should\s+not|do\s+not|don'?t|never|prohibited|forbidden|avoid|"
    r"not\s+allowed|not\s+permitted)\b[^.!?]*:?\s*$",
    re.IGNORECASE,
)

#: An introduction that puts everything after it in the positive, which ends a
#: prohibition's reach.
POSITIVE_INTRO = re.compile(
    r"(?:must|should|required|requirements?|steps?|procedure|how\s+to|to\s+do\s+this|"
    r"best\s+practice)\b[^.!?]*:?\s*$",
    re.IGNORECASE,
)

#: A bullet has to *do* something to be an action. Without this the extractor returned
#: fragments of lists - "Single sign-on;", "A keyboard pattern (`qwerty1234`)" - which
#: are configuration values and prohibited examples, not instructions.
ACTION_VERBS = frozenset(
    {
        "be", "use", "keep", "store", "enable", "require", "rotate", "report", "contact",
        "change", "check", "verify", "review", "remove", "install", "update", "configure",
        "ensure", "confirm", "notify", "follow", "apply", "replace", "delete", "set",
        "choose", "sign", "share", "write", "send", "ask", "tell", "run", "take",
        "disconnect", "wipe", "reset", "monitor", "validate", "restrict", "limit",
        "protect", "approve", "reject", "escalate", "open", "close", "log", "record",
        "turn", "switch", "join", "leave", "stop", "start", "provide", "give",
        "put", "make", "avoid", "never", "always", "must", "should", "do", "don't",
    }
)

#: Phrases that indicate a configuration value rather than an action.
NON_ACTION_HINTS = ("for example", "such as", "e.g.")

#: Returned when nothing in the retrieved context survives the polarity filter. A field
#: the UI renders and the ticket description quotes must not be empty, and "ask the
#: service desk" is the one action that is always true of a security assistant.
DEFAULT_ACTIONS = ("Contact the IT service desk if this does not answer your question.",)

MAX_ACTIONS = 5


@dataclasses.dataclass(frozen=True, slots=True)
class GeneratedAnswer:
    """The model output plus everything the caller needs to audit or render it."""

    answer: str
    recommended_actions: list[str]
    source_documents: list[dict[str, object]]
    cited_document_ids: list[str]
    grounded: bool
    provider: str
    model: str
    offline: bool
    retrieval: RetrievalResult
    #: Instruction-like text found inside the retrieved context and removed
    #: before the model saw it. Recorded for the audit trail.
    context_findings: tuple[GuardFinding, ...] = ()

    @property
    def has_sources(self) -> bool:
        return bool(self.source_documents)

    @property
    def context_had_injection(self) -> bool:
        return bool(self.context_findings)


def extract_actions(context: str, *, limit: int = MAX_ACTIONS) -> list[str]:
    """Pull actionable instructions out of the retrieved context.

    Deterministic extraction rather than a second model call: it keeps the
    offline path honest (every action is traceable to a document) and it costs
    nothing. Phase 6 consumes these when deciding what a ticket should say.

    **Polarity matters more than recall here.** A security policy is written as a
    mixture of requirements and prohibitions, and the first version of this function
    lifted both indiscriminately: asked "Show me the password policy" it recommended
    "Write passwords on paper kept at your desk", "Save passwords in plain text files"
    and "Share a password with a colleague" - the policy's *prohibitions* - and it
    turned "Never approve an MFA prompt you did not initiate" into "Approve an MFA
    prompt...", because the pattern stripped the leading "never" and kept the verb.
    Recommending the prohibited practice is worse than recommending nothing, so:

    * a line whose own opening is negative is dropped;
    * a bullet under a negative introduction ("Passwords must not be:", "Do not:") is
      dropped, even though the bullet itself contains no negative word;
    * a bullet has to open with something that *does* something - the lists of
      permitted mechanisms and prohibited examples are not instructions.

    Lines truncated by a chunk boundary are skipped rather than shown as
    half-sentences. An empty result is a legitimate outcome; the caller substitutes
    ``DEFAULT_ACTIONS``.
    """
    actions: list[str] = []
    seen: set[str] = set()
    prohibitions_in_force = False

    for sentence in split_sentences(context):
        stripped = sentence.strip()

        # Track which side of the policy we are on. An introduction governs the
        # bullets that follow it; a positive one ends a prohibition's reach.
        if NEGATIVE_INTRO.search(stripped):
            prohibitions_in_force = True
        elif POSITIVE_INTRO.search(stripped) and not NEGATIVE_INTRO.search(stripped):
            prohibitions_in_force = False

        if NEGATIVE_OPENING.match(stripped):
            prohibitions_in_force = prohibitions_in_force or stripped.endswith(":")
            continue

        for pattern in ACTION_PATTERNS:
            match = pattern.match(stripped)
            if not match:
                continue
            action = match.group("action").strip().rstrip(".")
            lowered = action.lower()
            if len(action) < 15 or len(action) > 220:
                break
            if prohibitions_in_force or NEGATIVE_OPENING.match(action):
                break
            # Check the original line, not the extracted text: the bullet marker
            # is what tells the truncation heuristic that a lower-case opening is
            # legitimate here.
            if looks_truncated(stripped):
                break
            if any(hint in lowered for hint in NON_ACTION_HINTS):
                break
            first_word = re.split(r"[\s,]", lowered, maxsplit=1)[0]
            if first_word not in ACTION_VERBS:
                # "Single sign-on;" / "A keyboard pattern (`qwerty1234`)" - a value or
                # an example of what not to do, not an instruction.
                break
            if lowered in seen:
                break
            seen.add(lowered)
            actions.append(action[0].upper() + action[1:] if action else action)
            break
        if len(actions) >= limit:
            break

    return actions


class ResponseGenerator:
    """Turns a retrieval result into an answer."""

    def _offline_completion(self, *, context: str, question: str, role: Role) -> LLMResponse:
        """Answer from the retrieved context without any provider.

        The fallback of last resort: the model is unreachable, but the authorised
        documents are already in memory, so the deterministic extractive
        generator can still produce a grounded, cited answer. It reports itself as
        the ``offline-fallback`` provider so the payload says honestly which path
        answered rather than implying the configured model did.
        """
        fallback = MockLLMClient()
        completion = fallback.complete(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=build_user_prompt(
                question=question, role=role, document_titles=[]
            ),
            context_block=context,
        )
        return replace(completion, provider="offline-fallback")

    def __init__(
        self,
        settings: Settings | None = None,
        client: LLMClient | None = None,
        guard: PromptGuard | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client or get_llm_client(self._settings)
        self._guard = guard or PromptGuard()

    @property
    def client(self) -> LLMClient:
        return self._client

    @property
    def guard(self) -> PromptGuard:
        return self._guard

    def generate(self, *, question: str, role: Role, retrieval: RetrievalResult) -> GeneratedAnswer:
        """Produce a grounded answer for an already-authorised retrieval."""
        sources = retrieval.sources
        cited = retrieval.cited_document_ids

        if not retrieval.has_matches:
            return GeneratedAnswer(
                answer=build_no_context_answer(role=role),
                recommended_actions=[],
                source_documents=[],
                cited_document_ids=[],
                grounded=False,
                provider="none",
                model="none",
                offline=True,
                retrieval=retrieval,
            )

        context = retrieval.context(max_chars=self._settings.retrieval_max_context_chars)
        # Retrieved text is data, but a document could still contain text that
        # reads like an instruction. Remove those lines before the model sees
        # them rather than trusting the model to ignore them.
        context, context_findings = self._guard.scan_context(context)
        titles = [str(source["title"]) for source in sources]

        user_prompt = build_user_prompt(question=question, role=role, document_titles=titles)
        try:
            completion = self._client.complete(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                context_block=context,
            )
        except Exception:
            # A provider that is down, rate-limiting or timing out must not cost
            # the user their answer. The retrieved, authorised documents are
            # already in hand, so fall back to the offline extractive generator
            # over the same context: same sources, same citations, no model.
            logger.warning(
                "llm_call_failed provider=%s - falling back to the offline generator",
                self._client.name,
                exc_info=True,
            )
            completion = self._offline_completion(context=context, question=question, role=role)

        answer = completion.text.strip()
        if not answer:
            # A provider that returns nothing must not produce a silent empty
            # answer. Which fallback is honest depends on whether retrieval found
            # anything: with no matches the assistant has nothing, but with matches
            # it has documents it simply could not quote - and claiming "I do not
            # have an approved knowledge document" while citing two of them
            # contradicts the same response.
            logger.warning(
                "llm_returned_empty provider=%s question_len=%d",
                completion.provider,
                len(question),
            )
            answer = (
                build_unextractable_answer(role=role)
                if retrieval.has_matches
                else build_no_context_answer(role=role)
            )

        actions = extract_actions(context) or list(DEFAULT_ACTIONS)

        return GeneratedAnswer(
            answer=answer,
            recommended_actions=actions,
            source_documents=sources,
            cited_document_ids=cited,
            grounded=True,
            provider=completion.provider,
            model=completion.model,
            offline=completion.offline,
            retrieval=retrieval,
            context_findings=context_findings,
        )

    def describe_provider(self) -> dict[str, object]:
        return {
            "provider": self._client.name,
            "model": self._client.model,
            "offline": self._client.is_offline,
        }


def audit_generation(completion: LLMResponse) -> dict[str, object]:
    """Metadata-only summary of a completion for the audit log."""
    return {
        "provider": completion.provider,
        "model": completion.model,
        "offline": completion.offline,
        "answer_chars": len(completion.text),
    }
