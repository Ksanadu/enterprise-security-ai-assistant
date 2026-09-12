"""Retrieval-Augmented Generation: knowledge base, embeddings, vector search.

The retrieval path is deliberately structured so that **authorization happens
before scoring**:

    role -> rbac.authorized_document_ids()  ->  VectorStore.search(allowed_ids=...)

No component in this package ever searches the full index and filters the
results afterwards, because that would leak the existence and content of
restricted documents through result counts and score ordering.
"""

from app.rag.documents import Chunk, KnowledgeDocument, ScoredChunk
from app.rag.retriever import RetrievalResult, Retriever

__all__ = [
    "Chunk",
    "KnowledgeDocument",
    "RetrievalResult",
    "Retriever",
    "ScoredChunk",
]
