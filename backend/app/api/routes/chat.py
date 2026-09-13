"""Chat endpoints.

The assistant surface. Every route resolves the caller from the bearer token,
checks conversation ownership in the service layer, and passes the caller's
*role* - never a client-supplied scope - into retrieval.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request, Response, status

from app.api.deps import AppSettings, CurrentUser, DbSession, client_ip, per_user_limiter
from app.core.enums import AuditOutcome, Role
from app.db.models import Conversation, Message
from app.schemas.chat import (
    ConversationDetail,
    ConversationListResponse,
    ConversationSummary,
    CreateConversationRequest,
    MessageOut,
    MessagePayload,
    PostMessageRequest,
    PostMessageResponse,
)
from app.security.audit import AuditAction, record_audit
from app.security.rate_limit import SlidingWindowLimiter
from app.services.chat_service import ChatService
from app.services.knowledge_service import KnowledgeService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["chat"])


def get_knowledge(request: Request) -> KnowledgeService:
    from app.api.routes.knowledge import get_knowledge_service

    return get_knowledge_service(request)


def get_chat_service(request: Request) -> ChatService:
    service = getattr(request.app.state, "chat", None)
    if service is None:  # pragma: no cover - only if lifespan did not run
        service = ChatService(get_knowledge(request), request.app.state.settings)
        request.app.state.chat = service
    return service


def message_limiter(request: Request, settings: AppSettings) -> SlidingWindowLimiter:
    """Per-process limiter for chat messages, created once per application."""
    return per_user_limiter(
        request, name="chat_limiter", limit=settings.chat_rate_limit_per_minute
    )


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else None


def to_message_out(message: Message) -> MessageOut:
    payload = MessagePayload(**message.payload) if message.payload else None
    return MessageOut(
        id=message.id,
        conversation_id=message.conversation_id,
        role=message.role.value,
        content=message.content,
        payload=payload,
        created_at=_iso(message.created_at),
    )


def to_summary(conversation: Conversation, message_count: int) -> ConversationSummary:
    return ConversationSummary(
        id=conversation.id,
        title=conversation.title,
        message_count=message_count,
        created_at=_iso(conversation.created_at),
        updated_at=_iso(conversation.updated_at),
    )


@router.get(
    "/conversations",
    response_model=ConversationListResponse,
    summary="List the caller's conversations",
)
def list_conversations(
    request: Request, user: CurrentUser, session: DbSession
) -> ConversationListResponse:
    chat = get_chat_service(request)
    conversations = chat.list_conversations(session, user=user)
    summaries = [
        to_summary(conversation, chat.message_count(session, conversation.id))
        for conversation in conversations
    ]
    return ConversationListResponse(count=len(summaries), conversations=summaries)


@router.post(
    "/conversations",
    response_model=ConversationSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new conversation",
)
def create_conversation(
    payload: CreateConversationRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> ConversationSummary:
    chat = get_chat_service(request)
    conversation = chat.create_conversation(session, user=user, title=payload.title)
    session.commit()
    return to_summary(conversation, 0)


@router.get(
    "/conversations/{conversation_id}",
    response_model=ConversationDetail,
    summary="Read one of the caller's conversations",
)
def get_conversation(
    conversation_id: int,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> ConversationDetail:
    chat = get_chat_service(request)
    conversation = chat.get_owned_conversation(session, user=user, conversation_id=conversation_id)
    messages = chat.list_messages(session, conversation)
    summary = to_summary(conversation, len(messages))
    return ConversationDetail(
        **summary.model_dump(), messages=[to_message_out(m) for m in messages]
    )


@router.delete(
    "/conversations/{conversation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete one of the caller's conversations",
)
def delete_conversation(
    conversation_id: int,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> Response:
    chat = get_chat_service(request)
    chat.delete_conversation(session, user=user, conversation_id=conversation_id)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=PostMessageResponse,
    summary="Send a message and receive a grounded answer with citations",
)
def post_message(
    conversation_id: int,
    payload: PostMessageRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
    settings: AppSettings,
) -> PostMessageResponse:
    chat = get_chat_service(request)
    conversation = chat.get_owned_conversation(session, user=user, conversation_id=conversation_id)

    # Throttle before doing any expensive work (embedding, search, model call).
    message_limiter(request, settings).check(f"chat:{user.id}")

    record_audit(
        session,
        action=AuditAction.QUERY_RECEIVED,
        actor=user,
        resource_type="conversation",
        resource_id=conversation.id,
        detail={"role": user.role.value, "question_chars": len(payload.content)},
        ip_address=client_ip(request),
    )

    user_message, assistant_message, generated, analysis = chat.post_message(
        session, user=user, conversation=conversation, content=payload.content
    )

    record_audit(
        session,
        action=AuditAction.QUERY_ANSWERED,
        actor=user,
        resource_type="conversation",
        resource_id=conversation.id,
        detail={
            **generated.retrieval.audit_detail(),
            "provider": generated.provider,
            "grounded": generated.grounded,
            "answer_chars": len(generated.answer),
            **analysis.audit_detail(),
        },
        ip_address=client_ip(request),
    )
    if analysis.blocked:
        record_audit(
            session,
            action=AuditAction.QUERY_BLOCKED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="conversation",
            resource_id=conversation.id,
            detail=analysis.guard.audit_detail(),
            ip_address=client_ip(request),
        )
    if analysis.requires_escalation:
        # Creating the ticket is Phase 6's job. Recording the decision now means
        # the security team has the signal even if ticket creation later fails.
        record_audit(
            session,
            action=AuditAction.ESCALATION_TRIGGERED,
            actor=user,
            resource_type="conversation",
            resource_id=conversation.id,
            detail={
                "risk_level": analysis.risk.level.value,
                "signals": [signal.label for signal in analysis.risk.signals],
                "reason": analysis.risk.reason,
            },
            ip_address=client_ip(request),
        )
    if generated.retrieval.dropped_unauthorized:
        record_audit(
            session,
            action=AuditAction.RETRIEVAL_DENIED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="conversation",
            resource_id=conversation.id,
            detail={"dropped_unauthorized": generated.retrieval.dropped_unauthorized},
            ip_address=client_ip(request),
        )
    session.commit()

    return PostMessageResponse(
        conversation_id=conversation.id,
        user_message=to_message_out(user_message),
        assistant_message=to_message_out(assistant_message),
    )


@router.get(
    "/capabilities",
    summary="What the assistant can currently do, for the calling role",
)
def capabilities(request: Request, user: CurrentUser, settings: AppSettings) -> dict[str, Any]:
    """Describes the assistant to the UI without exposing any configuration secret.

    Authenticated callers get the operational picture the footer and the sidebar
    need - which generator is answering, and which index is being searched. The
    *counts* inside the pipeline description (guard rules, intent rules, risk rules,
    the confidence threshold) are visible only to the security role: they describe
    the size of the pattern-matching gate and where its threshold sits, which is a
    map for anyone trying to get past it, and no other role needs them to use the
    product.
    """
    chat = get_chat_service(request)
    knowledge = get_knowledge(request)
    from app.security.rbac import describe_role

    scope = describe_role(user.role, knowledge.index.documents)
    detailed = user.role is Role.SECURITY
    return {
        "role": user.role.value,
        "role_label": user.role.label,
        "scope_description": scope["description"],
        "document_count": scope["document_count"],
        "provider": chat.describe_provider(),
        "pipeline": describe_pipeline_for(chat.describe_pipeline(), detailed=detailed),
        "knowledge_ready": knowledge.is_ready(),
        "categories": knowledge.categories(user.role),
        "retrieval": {
            "vector_store": settings.vector_store,
            "top_k": settings.retrieval_top_k,
        },
    }


def describe_pipeline_for(pipeline: dict[str, Any], *, detailed: bool) -> dict[str, Any]:
    """The pipeline description, with the rule counts removed for non-security roles.

    Kept as a function rather than a comprehension so the reduction is explicit and
    testable: everything an ordinary role receives is a capability flag, never a
    count.
    """
    if detailed:
        return pipeline

    guard = pipeline.get("guard", {})
    intent = pipeline.get("intent", {})
    risk = pipeline.get("risk", {})
    return {
        "guard": {"enabled": guard.get("enabled", False)},
        "intent": {"model_available": intent.get("model_available", False)},
        # Which levels a human is called for is published policy (KB-009), so it
        # stays: a user needs it to understand why they were escalated.
        "risk": {"escalation_levels": risk.get("escalation_levels", [])},
        "workflow": pipeline.get("workflow", {}),
    }
