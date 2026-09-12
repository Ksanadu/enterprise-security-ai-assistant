"""Authorisation-filtered retrieval.

The retrieval pipeline, in order:

1. Resolve the set of document ids the **role** may read, from the document
   metadata loaded from disk (``security.rbac.authorized_document_ids``).
2. Embed the query.
3. Search the vector store **with that allow-list**, so restricted vectors are
   never scored.
4. Drop matches below the similarity threshold.
5. Re-verify every surviving chunk against the policy (defence in depth) and
   drop anything that does not pass, counting it for the audit trail.
6. Assemble a size-bounded context block for the model.

Nothing in this module ever sees, or can return, a chunk the caller's role may
not read - including in counts, scores or ordering.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any

from app.core.config import Settings, get_settings
from app.core.enums import Role
from app.rag.documents import ScoredChunk
from app.rag.index import KnowledgeIndex
from app.security.rbac import permits

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class RetrievalResult:
    """Outcome of one retrieval, including the audit-relevant counters."""

    query: str
    role: Role
    matches: tuple[ScoredChunk, ...]
    allowed_document_ids: frozenset[str]
    indexed_documents: int
    authorized_documents: int
    considered_chunks: int
    dropped_below_threshold: int
    #: Matches discarded because they scored below the relative floor - they
    #: passed the absolute threshold but were far weaker than the best match.
    dropped_relative: int
    #: Chunks the vector store returned that failed the policy re-check. A
    #: non-zero value means the index and the on-disk policy disagree; it is
    #: treated as a security event, and the chunks are discarded.
    dropped_unauthorized: int

    @property
    def has_matches(self) -> bool:
        return bool(self.matches)

    @property
    def withheld_documents(self) -> int:
        """Documents excluded by the policy. Recorded in the audit log only -
        it is never sent to the model or shown to the user."""
        return max(0, self.indexed_documents - self.authorized_documents)

    @property
    def sources(self) -> list[dict[str, Any]]:
        """Citations for the chunks that were actually used, best match first."""
        return [match.to_reference() for match in self.matches]

    @property
    def cited_document_ids(self) -> list[str]:
        seen: list[str] = []
        for match in self.matches:
            if match.chunk.document_id not in seen:
                seen.append(match.chunk.document_id)
        return seen

    def context(self, max_chars: int) -> str:
        """Build the grounded context block for the model.

        Each block is labelled with its document id, title and section so the
        model can cite precisely - and so a citation can be verified against the
        sources list afterwards.
        """
        if not self.matches:
            return ""

        blocks: list[str] = []
        used = 0
        for index, match in enumerate(self.matches, start=1):
            chunk = match.chunk
            header = f"[{index}] {chunk.document_id} — {chunk.title} › {chunk.section}"  # noqa: RUF001
            body = chunk.text.strip()
            block = f"{header}\n{body}"
            if used + len(block) > max_chars and blocks:
                break
            blocks.append(block)
            used += len(block) + 2

        return "\n\n".join(blocks)

    def audit_detail(self) -> dict[str, Any]:
        """Metadata-only summary safe to write to the audit log."""
        return {
            "role": self.role.value,
            "indexed_documents": self.indexed_documents,
            "authorized_documents": self.authorized_documents,
            "withheld_documents": self.withheld_documents,
            "considered_chunks": self.considered_chunks,
            "returned_chunks": len(self.matches),
            "dropped_below_threshold": self.dropped_below_threshold,
            "dropped_relative": self.dropped_relative,
            "dropped_unauthorized": self.dropped_unauthorized,
            "cited_documents": self.cited_document_ids,
            "top_score": round(self.matches[0].score, 4) if self.matches else None,
        }


class Retriever:
    """Retrieves knowledge chunks for a role, never outside its scope."""

    def __init__(self, index: KnowledgeIndex, settings: Settings | None = None) -> None:
        self._index = index
        self._settings = settings or index.settings or get_settings()

    @property
    def index(self) -> KnowledgeIndex:
        return self._index

    def retrieve(
        self,
        query: str,
        *,
        role: Role,
        top_k: int | None = None,
        min_score: float | None = None,
        relative_floor: float | None = None,
    ) -> RetrievalResult:
        """Retrieve the best authorised chunks for ``query``."""
        top_k = self._settings.retrieval_top_k if top_k is None else top_k
        min_score = self._settings.retrieval_min_score if min_score is None else min_score
        relative_floor = (
            self._settings.retrieval_relative_floor if relative_floor is None else relative_floor
        )

        allowed_ids = self._index.authorized_document_ids(role)
        authorized_documents = len(allowed_ids)
        indexed_documents = len(self._index.documents)

        if not self._index.is_built:
            logger.warning("retrieval_skipped reason=index_not_built")
            return RetrievalResult(
                query=query,
                role=role,
                matches=(),
                allowed_document_ids=allowed_ids,
                indexed_documents=indexed_documents,
                authorized_documents=authorized_documents,
                considered_chunks=0,
                dropped_below_threshold=0,
                dropped_relative=0,
                dropped_unauthorized=0,
            )

        cleaned = query.strip()
        if not cleaned:
            return RetrievalResult(
                query=query,
                role=role,
                matches=(),
                allowed_document_ids=allowed_ids,
                indexed_documents=indexed_documents,
                authorized_documents=authorized_documents,
                considered_chunks=self._index.authorized_chunk_count(role),
                dropped_below_threshold=0,
                dropped_relative=0,
                dropped_unauthorized=0,
            )

        query_vector = self._index.embedder.embed_query(cleaned)
        # Over-fetch, because the per-document cap and the score floors below can
        # discard candidates. Fetching exactly top_k would silently return fewer.
        fetch_k = max(top_k, min(top_k * 3, 30))
        candidates = self._index.store.search(
            query_vector,
            top_k=fetch_k,
            allowed_document_ids=allowed_ids,
        )

        accepted: list[ScoredChunk] = []
        dropped_below_threshold = 0
        dropped_unauthorized = 0
        per_document: dict[str, int] = {}
        max_per_document = max(1, self._settings.retrieval_max_per_document)

        for match in candidates:
            # Defence in depth: the store was already filtered, but a stale or
            # corrupted index must not be able to widen access. Fail closed.
            if not permits(match.chunk, role):
                dropped_unauthorized += 1
                logger.error(
                    "retrieval_unauthorized_chunk doc=%s chunk=%s role=%s",
                    match.chunk.document_id,
                    match.chunk.chunk_id,
                    role.value,
                )
                continue
            if match.score < min_score:
                dropped_below_threshold += 1
                continue

            seen = per_document.get(match.chunk.document_id, 0)
            if seen >= max_per_document:
                # Keep the context diverse: several near-identical chunks from
                # one document crowd out the second-best document.
                continue
            per_document[match.chunk.document_id] = seen + 1
            accepted.append(match)
            if len(accepted) >= top_k:
                break

        # Relative floor: keep only matches reasonably close to the best one.
        dropped_relative = 0
        if accepted and relative_floor > 0:
            cutoff = accepted[0].score * relative_floor
            kept = [match for match in accepted if match.score >= cutoff]
            dropped_relative = len(accepted) - len(kept)
            accepted = kept

        result = RetrievalResult(
            query=cleaned,
            role=role,
            matches=tuple(accepted),
            allowed_document_ids=allowed_ids,
            indexed_documents=indexed_documents,
            authorized_documents=authorized_documents,
            considered_chunks=self._index.authorized_chunk_count(role),
            dropped_below_threshold=dropped_below_threshold,
            dropped_relative=dropped_relative,
            dropped_unauthorized=dropped_unauthorized,
        )
        logger.info(
            "retrieval_done role=%s returned=%d considered=%d withheld_docs=%d",
            role.value,
            len(accepted),
            result.considered_chunks,
            result.withheld_documents,
        )
        return result
