"""Knowledge service: owns the index and exposes role-scoped read operations.

The service is the only thing the API layer talks to. Every method that returns
content takes a :class:`Role` and goes through the RBAC-filtered retriever, so a
route cannot accidentally read the index directly.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.config import Settings
from app.core.enums import Role
from app.core.errors import AppError
from app.rag.index import IndexStats, KnowledgeIndex
from app.rag.retriever import RetrievalResult, Retriever
from app.security.rbac import describe_role

logger = logging.getLogger(__name__)


class KnowledgeUnavailableError(AppError):
    status_code = 503
    code = "knowledge_unavailable"
    message = "The knowledge base is not available."


class KnowledgeService:
    """Loads the knowledge base at startup and serves scoped queries."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._index = KnowledgeIndex(settings)
        self._retriever = Retriever(self._index, settings)

    # -- lifecycle --------------------------------------------------------
    def startup(self) -> IndexStats:
        """Build the index. Called from the application lifespan."""
        return self._index.build()

    def reindex(self) -> IndexStats:
        """Force a full rebuild, ignoring the cached vectors."""
        logger.info("knowledge_reindex_requested")
        return self._index.refresh()

    # -- reads ------------------------------------------------------------
    @property
    def index(self) -> KnowledgeIndex:
        return self._index

    def is_ready(self) -> bool:
        return self._index.is_built

    def stats(self) -> dict[str, Any]:
        """Index health for `/health` and the dashboard. Contains no content."""
        stats = self._index.stats
        return {
            **stats.to_dict(),
            "knowledge_base_dir": str(self._settings.knowledge_base_dir),
            "ready": self._index.is_built,
        }

    def documents_for(self, role: Role) -> list[dict[str, Any]]:
        """Metadata for every document ``role`` may read."""
        return [document.to_metadata() for document in self._index.documents_for(role)]

    def document_for(self, role: Role, document_id: str) -> dict[str, Any] | None:
        """A single authorised document including its body, or ``None``.

        Returning ``None`` for both "does not exist" and "not permitted" keeps
        the endpoint from confirming the existence of restricted documents.
        """
        for document in self._index.documents_for(role):
            if document.document_id == document_id:
                payload = document.to_metadata()
                payload["content"] = document.content
                return payload
        return None

    def search(
        self,
        query: str,
        *,
        role: Role,
        top_k: int | None = None,
    ) -> RetrievalResult:
        """Authorisation-filtered retrieval."""
        if not self._index.is_built:
            raise KnowledgeUnavailableError()
        return self._retriever.retrieve(query, role=role, top_k=top_k)

    def context_for(self, query: str, *, role: Role, top_k: int | None = None) -> RetrievalResult:
        """Alias used by the chat pipeline (Phase 5)."""
        return self.search(query, role=role, top_k=top_k)

    def role_scope(self, requester: Role) -> list[dict[str, Any]]:
        """Explain what each role can reach.

        Every role gets every role's description and document **count** - that is
        policy, and a user needs it to understand why an answer was narrow. Only
        the requester's own document ids are listed. Handing an employee the ids
        of the security team's investigation playbooks would be a target list,
        and would contradict the deliberate 404 (rather than 403) for a document
        the caller may not read.
        """
        return [
            describe_role(role, self._index.documents, include_document_ids=role is requester)
            for role in Role
        ]

    def categories(self, role: Role) -> dict[str, int]:
        counts: dict[str, int] = {}
        for document in self._index.documents_for(role):
            counts[document.category] = counts.get(document.category, 0) + 1
        return dict(sorted(counts.items()))
