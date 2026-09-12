"""Chat service: conversations, messages, and the assistant pipeline.

Security properties enforced here rather than in the route layer:

* **Ownership.** Every conversation lookup takes the caller and returns "not
  found" for a conversation they do not own. A wrong-owner lookup is
  indistinguishable from a missing one, so conversation ids cannot be probed.
* **Scope.** The retrieval step is given the caller's *role*, never a set of
  document ids from the request. The service has no way to ask for more.
* **Escalation.** The decision to involve a human is taken from the assessed
  risk level in backend code. No model output can lower it, and within a
  conversation the level only ever rises.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.intent_classifier import IntentClassifier
from app.ai.prompt_guard import GuardResult, PromptGuard
from app.ai.response_generator import GeneratedAnswer, ResponseGenerator
from app.ai.risk_classifier import RiskAssessment, RiskClassifier, highest_level
from app.ai.turn_analysis import TurnAnalysis
from app.core.config import Settings
from app.core.enums import AuditOutcome, Intent, MessageRole, RiskLevel, Role
from app.core.errors import AppError, NotFoundError, ValidationError
from app.db.models import Conversation, Message, Ticket, User
from app.rag.embeddings import tokenize
from app.rag.retriever import RetrievalResult
from app.security.audit import AuditAction, record_audit
from app.security.redaction import redact_credentials
from app.services.knowledge_service import KnowledgeService, KnowledgeUnavailableError
from app.services.workflow_manager import WorkflowDecision, WorkflowManager

logger = logging.getLogger(__name__)


class ChatUnavailableError(AppError):
    status_code = 503
    code = "chat_unavailable"
    message = "The assistant is temporarily unavailable."


DEFAULT_CONVERSATION_TITLE = "New conversation"
MAX_TITLE_CHARS = 120
#: How many previous user turns contribute context to the retrieval query.
QUERY_CONTEXT_TURNS = 2
#: A question carrying fewer content terms than this cannot stand on its own.
MIN_STANDALONE_TERMS = 2
#: Words that refer back to something said earlier.
BACK_REFERENCES = frozenset(
    {
        "else",
        "again",
        "also",
        "another",
        "further",
        "more",
        "same",
        "above",
        "previous",
        "earlier",
    }
)


def needs_conversation_context(question: str) -> bool:
    """True when a question cannot be understood without the previous turn.

    Expanding every question with history is actively harmful: the extra terms
    dilute the query vector and a self-contained question such as "What are the
    password requirements?" starts retrieving the wrong document. Expansion is
    therefore limited to questions that are genuinely dependent on context.
    """
    terms = tokenize(question)
    if len(terms) < MIN_STANDALONE_TERMS:
        return True
    words = set(re.findall(r"[a-z]+", question.lower()))
    return bool(words & BACK_REFERENCES)


def build_retrieval_query(history: list[str], question: str, *, max_chars: int) -> str:
    """Combine recent turns with the current question when it needs them.

    A follow-up like "what should I do?" carries no topical signal on its own and
    retrieves poorly. Prepending the previous user turns restores the subject.

    This is deliberately a deterministic, lexical expansion rather than an LLM
    rewrite: it costs nothing, it cannot be manipulated into widening retrieval
    (the authorisation filter is unaffected either way), and a model-based
    rewrite can be added in Phase 5 without changing this contract.
    """
    current = question.strip()
    if not history or not needs_conversation_context(current):
        return current[:max_chars]

    recent = [turn.strip() for turn in history[-QUERY_CONTEXT_TURNS:] if turn.strip()]
    if not recent:
        return current[:max_chars]

    prefix = " ".join(recent)
    budget = max_chars - len(current) - 1
    if budget <= 0:
        return current[:max_chars]
    return f"{prefix[:budget]} {current}".strip()


class ChatService:
    """Conversation and message operations for one request at a time."""

    def __init__(
        self,
        knowledge: KnowledgeService,
        settings: Settings,
        generator: ResponseGenerator | None = None,
        guard: PromptGuard | None = None,
        intent_classifier: IntentClassifier | None = None,
        risk_classifier: RiskClassifier | None = None,
        workflow: WorkflowManager | None = None,
    ) -> None:
        self._knowledge = knowledge
        self._settings = settings
        self._guard = guard or PromptGuard()
        self._generator = generator or ResponseGenerator(settings, guard=self._guard)
        self._intent_classifier = intent_classifier or IntentClassifier(settings)
        self._risk_classifier = risk_classifier or RiskClassifier(settings)
        self._workflow = workflow or WorkflowManager()

    # -- introspection ----------------------------------------------------
    def describe_pipeline(self) -> dict[str, object]:
        """What each pipeline stage is using. Contains no secret."""
        return {
            "generator": self._generator.describe_provider(),
            "guard": self._guard.describe(),
            "intent": self._intent_classifier.describe(),
            "risk": self._risk_classifier.describe(),
            "workflow": {
                "auto_ticket_risk_levels": ["high", "critical"],
                "tracked_risk_levels": ["medium"],
                "suggested_for_intents": ["it_support"],
            },
        }

    def describe_provider(self) -> dict[str, object]:
        """Which generator is answering. Contains no configuration secret."""
        return self._generator.describe_provider()

    # -- conversations ----------------------------------------------------
    def create_conversation(
        self, session: Session, *, user: User, title: str | None = None
    ) -> Conversation:
        conversation = Conversation(
            user_id=user.id,
            title=(title or DEFAULT_CONVERSATION_TITLE).strip()[:MAX_TITLE_CHARS]
            or DEFAULT_CONVERSATION_TITLE,
        )
        session.add(conversation)
        session.flush()
        logger.info("conversation_created id=%s user_id=%s", conversation.id, user.id)
        return conversation

    def get_owned_conversation(
        self, session: Session, *, user: User, conversation_id: int
    ) -> Conversation:
        """Fetch a conversation the caller owns.

        Raises:
            NotFoundError: when the conversation does not exist **or** belongs to
                somebody else. The two cases are intentionally identical.
        """
        conversation = session.scalar(
            select(Conversation).where(
                Conversation.id == conversation_id,
                Conversation.user_id == user.id,
            )
        )
        if conversation is None:
            # Do not distinguish "not yours" from "does not exist": an id probe
            # must not reveal that another user's conversation exists.
            logger.info(
                "conversation_access_denied conversation_id=%s user_id=%s",
                conversation_id,
                user.id,
            )
            record_audit(
                session,
                action=AuditAction.CONVERSATION_DENIED,
                outcome=AuditOutcome.DENIED,
                actor=user,
                resource_type="conversation",
                resource_id=conversation_id,
                detail={"reason": "not_owner_or_missing"},
                commit=True,
            )
            raise NotFoundError("Conversation not found.")
        return conversation

    def list_conversations(self, session: Session, *, user: User) -> list[Conversation]:
        """Only the caller's own conversations, newest first."""
        return list(
            session.scalars(
                select(Conversation)
                .where(Conversation.user_id == user.id)
                .order_by(Conversation.updated_at.desc(), Conversation.id.desc())
            ).all()
        )

    def message_count(self, session: Session, conversation_id: int) -> int:
        return int(
            session.scalar(
                select(func.count(Message.id)).where(Message.conversation_id == conversation_id)
            )
            or 0
        )

    def delete_conversation(self, session: Session, *, user: User, conversation_id: int) -> None:
        conversation = self.get_owned_conversation(
            session, user=user, conversation_id=conversation_id
        )
        session.delete(conversation)
        logger.info("conversation_deleted id=%s user_id=%s", conversation_id, user.id)

    # -- messages ---------------------------------------------------------
    def list_messages(self, session: Session, conversation: Conversation) -> list[Message]:
        return list(
            session.scalars(
                select(Message)
                .where(Message.conversation_id == conversation.id)
                .order_by(Message.id.asc())
            ).all()
        )

    def _recent_user_turns(self, session: Session, conversation: Conversation) -> list[str]:
        rows = session.scalars(
            select(Message)
            .where(
                Message.conversation_id == conversation.id,
                Message.role == MessageRole.USER,
            )
            .order_by(Message.id.desc())
            .limit(QUERY_CONTEXT_TURNS)
        ).all()
        return [row.content for row in reversed(rows)]

    def post_message(
        self, session: Session, *, user: User, conversation: Conversation, content: str
    ) -> tuple[Message, Message, GeneratedAnswer, TurnAnalysis]:
        """Record the user's message and produce the assistant's reply.

        The pipeline runs in the order the specification defines: guard, intent,
        authorisation-filtered retrieval, response generation, then risk. Risk is
        last because it can take the intent into account, and it is computed by
        backend rules rather than by the model.

        Returns ``(user_message, assistant_message, generated, analysis)``.
        """
        question = content.strip()
        if not question:
            raise ValidationError("Message must not be empty.")
        if len(question) > self._settings.max_query_length:
            raise ValidationError(
                f"Message exceeds the maximum length of {self._settings.max_query_length} "
                "characters."
            )
        if not self._knowledge.is_ready():
            raise KnowledgeUnavailableError()

        # A user reporting an incident may paste the credential they just lost
        # control of. Classification, retrieval and risk assessment below all run
        # on the raw text, because the wording is the signal. Nothing *persisted*
        # keeps the plaintext: this is the same rule the ticket body already
        # follows, applied to the message row and the title derived from it.
        stored_content = redact_credentials(question)

        user_message = Message(
            conversation_id=conversation.id,
            role=MessageRole.USER,
            content=stored_content,
        )
        session.add(user_message)
        session.flush()

        # 1. Guard. A request that tries to rewrite the assistant's rules, extract
        #    its configuration or bypass access control never reaches the model.
        guard_result = self._guard.scan_query(question)
        if guard_result.blocked:
            return self._handle_blocked_turn(
                session, conversation, user_message, guard_result, user.role
            )

        # 2. Intent. A bare follow-up ("what else should I know?") carries no
        #    topical signal on its own, so it is classified with the same
        #    conversation context retrieval uses. Without this it lands in
        #    "out of scope" and the follow-up loses the subject it was about.
        history = self._recent_user_turns(session, conversation)
        classification_text = (
            build_retrieval_query(history, question, max_chars=self._settings.max_query_length)
            if needs_conversation_context(question)
            else question
        )
        intent = self._intent_classifier.classify(classification_text)

        # 3. Retrieval, already filtered to what this role may read.
        #
        # A question the classifier placed outside the assistant's remit is not
        # answered from the knowledge base at all. Retrieval is lexical, so an
        # off-topic question ("explain the offside rule") still matches *some*
        # document, and answering from it produces a confident, cited, wrong
        # answer. Saying "that is outside what I cover" is the honest response.
        if intent.intent is Intent.OUT_OF_SCOPE:
            retrieval = self._empty_retrieval(question, user.role)
            logger.info("retrieval_skipped reason=out_of_scope")
        else:
            retrieval = self._retrieve(question=question, history=history, role=user.role)

        # 4. Grounded answer generation.
        generated = self._generator.generate(question=question, role=user.role, retrieval=retrieval)

        # 5. Risk, then the escalation decision - both in backend code.
        history_peak = RiskLevel(conversation.peak_risk_level)
        risk = self._risk_classifier.assess(
            question, intent=intent.intent, history_peak=history_peak
        )
        peak = highest_level([history_peak, risk.level])
        conversation.peak_risk_level = peak.value

        analysis = TurnAnalysis(
            intent=intent.intent,
            intent_confidence=intent.confidence,
            intent_source=intent.source,
            intent_signals=intent.signals,
            risk=risk,
            guard=guard_result,
            peak_risk=peak,
            context_findings=len(generated.context_findings),
        )

        # 6. Workflow decision: does this need a ticket, and does it need a person?
        #    The ticket side is performed here so the assistant's answer can name
        #    the reference it just created.
        ticket, decision = self._apply_workflow(
            session,
            analysis=analysis,
            user=user,
            conversation=conversation,
            question=question,
        )
        analysis = dataclasses.replace(
            analysis,
            ticket_reference=ticket.reference if ticket is not None else None,
            ticket_status=ticket.status.value if ticket is not None else None,
            workflow_action=decision.action,
            clarifying_question=decision.clarifying_question or None,
        )

        # The medium-risk tier answers by asking. The question belongs in the
        # answer itself, not only in the structured field, or the user reads a
        # complete-looking reply and never sees that something was asked of them.
        if decision.clarifying_question:
            generated = dataclasses.replace(
                generated, answer=f"{generated.answer}\n\n{decision.clarifying_question}"
            )

        assistant_message = Message(
            conversation_id=conversation.id,
            role=MessageRole.ASSISTANT,
            content=generated.answer,
            payload=self._build_payload(generated, analysis),
            source_document_ids=generated.cited_document_ids,
            # Denormalised for dashboard aggregation; the payload stays the full record.
            intent=analysis.intent.value,
            risk_level=analysis.risk.level.value,
            escalated=analysis.risk.requires_escalation,
        )
        session.add(assistant_message)

        self._maybe_title_conversation(conversation, stored_content)
        conversation.updated_at = dt.datetime.now(dt.UTC)
        session.flush()

        logger.info(
            "chat_answer conversation_id=%s role=%s sources=%d grounded=%s intent=%s risk=%s",
            conversation.id,
            user.role.value,
            len(generated.source_documents),
            generated.grounded,
            intent.intent.value,
            risk.level.value,
        )
        return user_message, assistant_message, generated, analysis

    def _handle_blocked_turn(
        self,
        session: Session,
        conversation: Conversation,
        user_message: Message,
        guard_result: GuardResult,
        role: Role,
    ) -> tuple[Message, Message, GeneratedAnswer, TurnAnalysis]:
        """Refuse a prompt-injection attempt without calling the model.

        The refusal is stored like any other turn, so the conversation reads
        naturally and the user can see what happened and why.
        """
        # Defined once and used for both the message body and the structured
        # payload, so the two cannot disagree.
        blocked_answer = (
            "I can't help with that request. It asks me to change my operating rules or to "
            "disclose material outside your access level, and I'm not able to do either — "
            "my instructions and the document permissions are enforced by the application, "
            "not by me.\n\n"
            "If you need access to a document you cannot currently read, ask the IT service "
            "desk or the security team to review your role."
        )

        assistant_message = Message(
            conversation_id=conversation.id,
            role=MessageRole.ASSISTANT,
            content=blocked_answer,
            payload={
                "answer": blocked_answer,
                "recommended_actions": [
                    "Contact the IT service desk if you need a role or access review",
                ],
                "source_documents": [],
                "grounded": False,
                "provider": "guard",
                "model": "none",
                "offline": True,
                "intent": Intent.OUT_OF_SCOPE.value,
                "intent_confidence": 0.0,
                "intent_source": "guard",
                "risk_level": RiskLevel.MEDIUM.value,
                "risk_signals": [],
                "risk_reason": "blocked by the prompt-injection guard",
                "human_escalation": False,
                "create_ticket": False,
                "peak_risk_level": conversation.peak_risk_level,
                "blocked": True,
                "block_reason": guard_result.reason,
                "block_categories": guard_result.categories,
                "context_injection_blocked": 0,
                "ticket_reference": None,
                "ticket_status": None,
            },
            source_document_ids=[],
            intent=Intent.OUT_OF_SCOPE.value,
            risk_level=RiskLevel.MEDIUM.value,
            escalated=False,
        )
        session.add(assistant_message)
        self._maybe_title_conversation(conversation, user_message.content)
        conversation.updated_at = dt.datetime.now(dt.UTC)
        session.flush()

        peak = RiskLevel(conversation.peak_risk_level)
        logger.warning(
            "chat_query_blocked conversation_id=%s categories=%s",
            conversation.id,
            guard_result.categories,
        )
        return (
            user_message,
            assistant_message,
            self._empty_generation(user_message.content, role),
            TurnAnalysis(
                intent=Intent.OUT_OF_SCOPE,
                intent_confidence=0.0,
                intent_source="guard",
                risk=RiskAssessment(
                    level=RiskLevel.MEDIUM,
                    signals=(),
                    source="guard",
                    reason="blocked by the prompt-injection guard",
                ),
                guard=guard_result,
                peak_risk=peak,
                blocked=True,
            ),
        )

    def _apply_workflow(
        self,
        session: Session,
        *,
        analysis: TurnAnalysis,
        user: User,
        conversation: Conversation,
        question: str,
    ) -> tuple[Ticket | None, WorkflowDecision]:
        """Run the workflow decision and perform it.

        Returns the affected ticket (or ``None``) *and* the decision, so the
        caller can record which tier the turn landed in and relay a clarifying
        question to the user.
        """
        existing = self._workflow.tickets.find_open_for_conversation(
            session, conversation_id=conversation.id
        )
        decision = self._workflow.decide(
            analysis=analysis, question=question, existing_ticket=existing
        )
        logger.info(
            "workflow_decision conversation_id=%s action=%s reason=%s risk=%s",
            conversation.id,
            decision.action,
            decision.reason,
            analysis.risk.level.value,
        )
        try:
            return (
                self._workflow.apply(
                    session,
                    decision=decision,
                    user=user,
                    analysis=analysis,
                    conversation_id=conversation.id,
                    question=question,
                    existing_ticket=existing,
                ),
                decision,
            )
        except Exception:
            # The answer has already been generated and is still worth delivering.
            # A ticket that could not be filed is an operational problem, not a
            # reason to lose the user's incident report on the floor - so this is
            # recorded loudly and the turn continues without a reference.
            logger.exception(
                "workflow_apply_failed conversation_id=%s action=%s risk=%s",
                conversation.id,
                decision.action,
                analysis.risk.level.value,
            )
            self._record_workflow_failure(
                session, conversation_id=conversation.id, user=user, decision=decision
            )
            return None, decision

    def _record_workflow_failure(
        self,
        session: Session,
        *,
        conversation_id: int,
        user: User,
        decision: WorkflowDecision,
    ) -> None:
        """Leave a trace that the workflow could not complete.

        Without this the only evidence would be a log line: the user is told to
        contact the service desk, and nobody can reconcile which reports failed to
        be filed.
        """
        try:
            record_audit(
                session,
                action=AuditAction.WORKFLOW_FAILED,
                actor=user,
                resource_type="conversation",
                resource_id=conversation_id,
                detail={
                    "action": decision.action,
                    "reason": decision.reason,
                    "severity": decision.severity.value,
                    "owner_role": decision.owner_role.value,
                },
                commit=True,
            )
        except Exception:
            # If even the audit write fails, do not escalate the failure further:
            # the request still deserves an answer.
            logger.exception("workflow_audit_failed conversation_id=%s", conversation_id)

    def _build_payload(
        self, generated: GeneratedAnswer, analysis: TurnAnalysis
    ) -> dict[str, object]:
        """The structured assistant response stored with each message.

        PRODUCT_SPEC.md section 8 fixes the shape of this object: intent,
        risk_level, answer, recommended_actions, source_documents,
        human_escalation, create_ticket. ``answer`` repeats the message body on
        purpose, so the payload is a complete, self-describing record rather than
        one that only makes sense next to its parent row - which is what an
        integration consuming the structured output needs.
        """
        risk = analysis.risk
        return {
            "answer": generated.answer,
            "recommended_actions": generated.recommended_actions,
            "source_documents": generated.source_documents,
            "grounded": generated.grounded,
            "provider": generated.provider,
            "model": generated.model,
            "offline": generated.offline,
            "intent": analysis.intent.value,
            "intent_confidence": round(analysis.intent_confidence, 2),
            "intent_source": analysis.intent_source,
            "risk_level": risk.level.value,
            "risk_signals": [
                {"label": signal.label, "level": signal.level.value, "evidence": signal.evidence}
                for signal in risk.signals
            ],
            "risk_reason": risk.reason,
            # Escalation is a backend decision taken from the level, never from
            # anything a model said.
            "human_escalation": risk.requires_escalation,
            "create_ticket": risk.requires_escalation,
            "peak_risk_level": analysis.peak_risk.value,
            "blocked": False,
            "context_injection_blocked": analysis.context_findings,
            "ticket_reference": analysis.ticket_reference,
            "ticket_status": analysis.ticket_status,
            "workflow_action": analysis.workflow_action,
            "clarifying_question": analysis.clarifying_question,
        }

    def _empty_retrieval(self, query: str, role: Role) -> RetrievalResult:
        """A retrieval result representing "nothing was searched".

        Used when the turn is answered without the knowledge base, either because
        the question is out of scope or because it was refused.
        """
        return RetrievalResult(
            query=query,
            role=role,
            matches=(),
            allowed_document_ids=frozenset(),
            indexed_documents=0,
            authorized_documents=0,
            considered_chunks=0,
            dropped_below_threshold=0,
            dropped_relative=0,
            dropped_unauthorized=0,
        )

    def _empty_generation(self, query: str, role: Role) -> GeneratedAnswer:
        """Placeholder generation result for a turn that never reached the model."""
        return GeneratedAnswer(
            answer="",
            recommended_actions=[],
            source_documents=[],
            cited_document_ids=[],
            grounded=False,
            provider="guard",
            model="none",
            offline=True,
            retrieval=self._empty_retrieval(query, role),
        )

    def _retrieve(self, *, question: str, history: list[str], role: Role) -> RetrievalResult:
        query = build_retrieval_query(history, question, max_chars=self._settings.max_query_length)
        try:
            return self._knowledge.search(query, role=role)
        except KnowledgeUnavailableError as exc:
            raise ChatUnavailableError() from exc

    @staticmethod
    def _maybe_title_conversation(conversation: Conversation, question: str) -> None:
        """Give an untitled conversation a useful name from its first question."""
        if conversation.title != DEFAULT_CONVERSATION_TITLE:
            return
        title = question.strip().splitlines()[0]
        if len(title) > MAX_TITLE_CHARS:
            title = title[: MAX_TITLE_CHARS - 1].rstrip() + "…"
        conversation.title = title or DEFAULT_CONVERSATION_TITLE
