"""Knowledge base endpoints.

Every endpoint derives the caller's role from the authenticated principal and
never from a request parameter. There is no "role" or "allowed_roles" field
anywhere in these schemas, by design.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.api.deps import AppSettings, CurrentUser, DbSession, client_ip, require_roles
from app.core.enums import AuditOutcome, Role
from app.core.errors import NotFoundError, ValidationError
from app.db.models import User
from app.schemas.knowledge import (
    DocumentDetail,
    DocumentListResponse,
    IndexStatsResponse,
    RoleScopeResponse,
    SearchRequest,
    SearchResponse,
)
from app.security.audit import AuditAction, record_audit
from app.services.knowledge_service import KnowledgeService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


def get_knowledge_service(request: Request) -> KnowledgeService:
    """Fetch the process-wide knowledge service from application state."""
    service = getattr(request.app.state, "knowledge", None)
    if service is None:  # pragma: no cover - only if lifespan did not run
        raise NotFoundError("Knowledge base is not initialised.")
    return service


@router.get(
    "/documents",
    response_model=DocumentListResponse,
    summary="List knowledge documents visible to the caller's role",
)
def list_documents(
    request: Request,
    user: CurrentUser,
    session: DbSession,
    settings: AppSettings,
) -> DocumentListResponse:
    service = get_knowledge_service(request)
    documents = service.documents_for(user.role)
    record_audit(
        session,
        action=AuditAction.KNOWLEDGE_LISTED,
        actor=user,
        resource_type="knowledge_base",
        detail={"role": user.role.value, "returned": len(documents)},
        ip_address=client_ip(request),
        commit=True,
    )
    return DocumentListResponse(
        role=user.role.value,
        count=len(documents),
        categories=service.categories(user.role),
        documents=documents,
    )


@router.get(
    "/documents/{document_id}",
    response_model=DocumentDetail,
    summary="Read one knowledge document if the caller's role permits it",
)
def get_document(
    document_id: str,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> DocumentDetail:
    service = get_knowledge_service(request)
    document = service.document_for(user.role, document_id)

    if document is None:
        # A permission failure is audited as a denial; the response is identical
        # to a genuine "not found" so the endpoint cannot be used to discover
        # which restricted documents exist.
        record_audit(
            session,
            action=AuditAction.DOCUMENT_ACCESS_DENIED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="knowledge_document",
            resource_id=document_id,
            detail={"role": user.role.value},
            ip_address=client_ip(request),
            commit=True,
        )
        raise NotFoundError("Document not found.")

    record_audit(
        session,
        action=AuditAction.DOCUMENT_VIEWED,
        actor=user,
        resource_type="knowledge_document",
        resource_id=document_id,
        detail={"role": user.role.value},
        ip_address=client_ip(request),
        commit=True,
    )
    return DocumentDetail(**document)


@router.post(
    "/search",
    response_model=SearchResponse,
    summary="Authorisation-filtered retrieval preview",
)
def search(
    payload: SearchRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
    settings: AppSettings,
) -> SearchResponse:
    """Retrieve chunks the caller is allowed to see.

    This endpoint exists to make the RBAC filter observable: the same query
    returns different sources for different roles.
    """
    if len(payload.query) > settings.max_query_length:
        raise ValidationError(
            f"Query exceeds the maximum length of {settings.max_query_length} characters."
        )

    service = get_knowledge_service(request)
    result = service.search(payload.query, role=user.role, top_k=payload.top_k)

    record_audit(
        session,
        action=AuditAction.RETRIEVAL_PERFORMED,
        actor=user,
        resource_type="knowledge_base",
        detail=result.audit_detail(),
        ip_address=client_ip(request),
        commit=True,
    )
    if result.dropped_unauthorized:
        record_audit(
            session,
            action=AuditAction.RETRIEVAL_DENIED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="knowledge_base",
            detail={"dropped_unauthorized": result.dropped_unauthorized},
            ip_address=client_ip(request),
            commit=True,
        )

    return SearchResponse(
        query=result.query,
        role=user.role.value,
        result_count=len(result.matches),
        results=[match.to_reference() for match in result.matches],
        no_authorized_match=not result.has_matches,
    )


@router.get(
    "/scope",
    response_model=RoleScopeResponse,
    summary="Describe what each role may read",
)
def role_scope(request: Request, _: CurrentUser) -> RoleScopeResponse:
    """Documentation-style view of the RBAC policy.

    Deliberately available to every authenticated role: knowing the policy is
    not a privilege, and it lets a user understand why an answer was narrow.
    """
    return RoleScopeResponse(roles=get_knowledge_service(request).role_scope())


@router.post(
    "/reindex",
    response_model=IndexStatsResponse,
    summary="Rebuild the vector index (security role only)",
)
def reindex(
    request: Request,
    user: Annotated[User, Depends(require_roles(Role.SECURITY))],
    session: DbSession,
) -> IndexStatsResponse:
    """Rebuild the index after the knowledge base changed.

    Restricted to the security role by the shared authorization dependency, so
    the denial and its audit entry follow the same path as every other protected
    endpoint rather than a hand-written check.
    """
    service = get_knowledge_service(request)
    stats = service.reindex()
    record_audit(
        session,
        action=AuditAction.REINDEX_PERFORMED,
        actor=user,
        resource_type="knowledge_base",
        detail={"documents": stats.document_count, "chunks": stats.chunk_count},
        ip_address=client_ip(request),
        commit=True,
    )
    return IndexStatsResponse(**service.stats(), reindexed=True)


@router.get(
    "/stats",
    response_model=IndexStatsResponse,
    summary="Vector index statistics",
)
def index_stats(request: Request, _: CurrentUser) -> IndexStatsResponse:
    """Index health. Reports counts only - never document titles or content."""
    return IndexStatsResponse(**get_knowledge_service(request).stats())
