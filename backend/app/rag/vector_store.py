"""Vector stores with an enforced pre-retrieval authorization filter.

The single most important design decision in this module: :meth:`VectorStore.search`
**requires** the caller to pass ``allowed_document_ids``. There is no default, no
``None`` escape hatch and no "search everything then filter" method. A caller
physically cannot retrieve from the full index by accident.

Filtering happens *inside* the search, before scoring:

* the in-memory store skips non-authorised vectors while scoring;
* the FAISS store restricts the scan with an ``IDSelector``, so scores for
  restricted documents are never computed, never returned, and cannot influence
  result counts or score ordering.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Any, Protocol

from app.core.enums import Role
from app.rag.documents import Chunk, ScoredChunk
from app.rag.embeddings import cosine_similarity

logger = logging.getLogger(__name__)

MAX_TOP_K = 50

MANIFEST_NAME = "index.json"
FAISS_INDEX_NAME = "faiss.index"


class VectorStore(Protocol):
    """Common interface for every vector store implementation."""

    @property
    def name(self) -> str: ...

    @property
    def size(self) -> int: ...

    def build(self, chunks: Sequence[Chunk], vectors: Sequence[Sequence[float]]) -> None: ...

    def search(
        self,
        query_vector: Sequence[float],
        *,
        top_k: int,
        allowed_document_ids: Collection[str],
    ) -> list[ScoredChunk]: ...

    def save(self, directory: Path) -> None: ...

    def load(self, directory: Path) -> bool: ...

    def document_ids(self) -> set[str]: ...


def _clamp_top_k(top_k: int) -> int:
    if top_k < 1:
        return 0
    return min(top_k, MAX_TOP_K)


def _chunk_to_manifest(chunk: Chunk) -> dict[str, Any]:
    return {
        "chunk_id": chunk.chunk_id,
        "document_id": chunk.document_id,
        "title": chunk.title,
        "category": chunk.category,
        "allowed_roles": sorted(role.value for role in chunk.allowed_roles),
        "section": chunk.section,
        "text": chunk.text,
        "position": chunk.position,
    }


def _chunk_from_manifest(entry: dict[str, Any]) -> Chunk:
    return Chunk(
        chunk_id=entry["chunk_id"],
        document_id=entry["document_id"],
        title=entry["title"],
        category=entry["category"],
        allowed_roles=frozenset(Role(value) for value in entry["allowed_roles"]),
        section=entry["section"],
        text=entry["text"],
        position=int(entry["position"]),
    )


class InMemoryVectorStore:
    """Dependency-free exact cosine search.

    Used as the default in tests and as the automatic fallback when FAISS is not
    installed. Complexity is linear in the number of authorised chunks, which is
    the right trade-off at this scale and keeps the authorization filter
    impossible to get wrong.
    """

    def __init__(self) -> None:
        self._chunks: list[Chunk] = []
        self._vectors: list[list[float]] = []
        self._by_document: dict[str, list[int]] = {}

    @property
    def name(self) -> str:
        return "memory"

    @property
    def size(self) -> int:
        return len(self._chunks)

    def build(self, chunks: Sequence[Chunk], vectors: Sequence[Sequence[float]]) -> None:
        if len(chunks) != len(vectors):
            raise ValueError("chunks and vectors must have the same length")
        self._chunks = list(chunks)
        self._vectors = [list(vector) for vector in vectors]
        self._by_document = {}
        for position, chunk in enumerate(self._chunks):
            self._by_document.setdefault(chunk.document_id, []).append(position)

    def search(
        self,
        query_vector: Sequence[float],
        *,
        top_k: int,
        allowed_document_ids: Collection[str],
    ) -> list[ScoredChunk]:
        limit = _clamp_top_k(top_k)
        allowed = set(allowed_document_ids)
        if limit == 0 or not allowed:
            # An empty allow-list means "this principal may read nothing".
            return []

        # Pre-filter: collect candidate offsets first, then score only those.
        candidates: list[int] = []
        for document_id in allowed:
            candidates.extend(self._by_document.get(document_id, ()))

        scored = [
            ScoredChunk(
                chunk=self._chunks[position],
                score=cosine_similarity(query_vector, self._vectors[position]),
            )
            for position in candidates
        ]
        scored.sort(key=lambda item: (-item.score, item.chunk.chunk_id))
        return scored[:limit]

    def document_ids(self) -> set[str]:
        return set(self._by_document)

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        manifest = {
            "kind": self.name,
            "chunks": [
                {**_chunk_to_manifest(chunk), "vector": list(vector)}
                for chunk, vector in zip(self._chunks, self._vectors, strict=True)
            ],
        }
        (directory / MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
        )

    def load(self, directory: Path) -> bool:
        manifest_path = directory / MANIFEST_NAME
        if not manifest_path.is_file():
            return False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("kind") != self.name:
                return False
            entries = manifest["chunks"]
            chunks = [_chunk_from_manifest(entry) for entry in entries]
            vectors = [[float(value) for value in entry["vector"]] for entry in entries]
        except (json.JSONDecodeError, OSError, KeyError, ValueError, TypeError):
            logger.warning("vector_store_load_failed path=%s", manifest_path)
            return False

        self.build(chunks, vectors)
        return True


class FaissVectorStore:
    """FAISS-backed exact search with a hard pre-filter.

    ``IndexFlatIP`` over L2-normalised vectors gives cosine similarity. The
    authorization filter is pushed into FAISS through an ``IDSelectorBatch``, so
    restricted vectors are skipped by the scan itself.
    """

    def __init__(self) -> None:
        import faiss  # imported lazily so the module imports without FAISS

        self._faiss = faiss
        self._index: Any = None
        self._chunks: list[Chunk] = []
        self._document_ids: set[str] = set()
        self._selector_supported = True

    @property
    def name(self) -> str:
        return "faiss"

    @property
    def size(self) -> int:
        return len(self._chunks)

    def build(self, chunks: Sequence[Chunk], vectors: Sequence[Sequence[float]]) -> None:
        import numpy as np

        if len(chunks) != len(vectors):
            raise ValueError("chunks and vectors must have the same length")
        self._chunks = list(chunks)
        self._document_ids = {chunk.document_id for chunk in self._chunks}

        if not vectors:
            self._index = None
            return

        matrix = np.asarray(vectors, dtype="float32")
        index = self._faiss.IndexFlatIP(matrix.shape[1])
        index.add(matrix)
        self._index = index

    def _allowed_rows(self, allowed_document_ids: Collection[str]) -> list[int]:
        allowed = self._document_ids & set(allowed_document_ids)
        if not allowed:
            return []
        return [
            position for position, chunk in enumerate(self._chunks) if chunk.document_id in allowed
        ]

    def search(
        self,
        query_vector: Sequence[float],
        *,
        top_k: int,
        allowed_document_ids: Collection[str],
    ) -> list[ScoredChunk]:
        import numpy as np

        limit = _clamp_top_k(top_k)
        if limit == 0 or self._index is None or not self._chunks:
            return []

        rows = self._allowed_rows(allowed_document_ids)
        if not rows:
            return []

        query = np.asarray([list(query_vector)], dtype="float32")

        if self._selector_supported:
            try:
                selector = self._faiss.IDSelectorBatch(np.asarray(rows, dtype="int64"))
                # faiss ships incomplete type information: `sel` is the documented
                # keyword for pre-filtering a search.
                params = self._faiss.SearchParameters(sel=selector)  # type: ignore[call-arg]
                scores, indices = self._index.search(query, limit, params=params)
                return self._collect(scores[0], indices[0])
            except (AttributeError, TypeError, RuntimeError) as exc:
                # Older FAISS builds cannot apply a selector to a flat index.
                # The fallback scores the authorised subset explicitly, which is
                # still a pre-filter - it never touches a restricted vector.
                logger.info(
                    "faiss_selector_unsupported fallback=subset reason=%s", type(exc).__name__
                )
                self._selector_supported = False

        return self._score_subset(query_vector, rows, limit)

    def _collect(self, scores: Any, indices: Any) -> list[ScoredChunk]:
        results: list[ScoredChunk] = []
        for score, row in zip(scores, indices, strict=True):
            if int(row) < 0:
                continue
            results.append(ScoredChunk(chunk=self._chunks[int(row)], score=float(score)))
        results.sort(key=lambda item: (-item.score, item.chunk.chunk_id))
        return results

    def _score_subset(
        self, query_vector: Sequence[float], rows: Sequence[int], limit: int
    ) -> list[ScoredChunk]:
        scored = [
            ScoredChunk(
                chunk=self._chunks[row],
                score=cosine_similarity(query_vector, self._reconstruct(row)),
            )
            for row in rows
        ]
        scored.sort(key=lambda item: (-item.score, item.chunk.chunk_id))
        return scored[:limit]

    def _reconstruct(self, row: int) -> list[float]:
        import numpy as np

        vector = np.zeros((1, self._index.d), dtype="float32")
        self._index.reconstruct(int(row), vector[0])
        return [float(value) for value in vector[0]]

    def document_ids(self) -> set[str]:
        return set(self._document_ids)

    def save(self, directory: Path) -> None:
        if self._index is None:
            return
        directory.mkdir(parents=True, exist_ok=True)
        self._faiss.write_index(self._index, str(directory / FAISS_INDEX_NAME))
        manifest = {
            "kind": self.name,
            "dimension": int(self._index.d),
            "chunks": [_chunk_to_manifest(chunk) for chunk in self._chunks],
        }
        (directory / MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
        )

    def load(self, directory: Path) -> bool:
        manifest_path = directory / MANIFEST_NAME
        index_path = directory / FAISS_INDEX_NAME
        if not manifest_path.is_file() or not index_path.is_file():
            return False

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("kind") != self.name:
                return False
            index = self._faiss.read_index(str(index_path))
            chunks = [_chunk_from_manifest(entry) for entry in manifest["chunks"]]
        except (json.JSONDecodeError, OSError, KeyError, ValueError, TypeError, RuntimeError):
            logger.warning("vector_store_load_failed path=%s", directory)
            return False

        if index.ntotal != len(chunks):
            logger.warning(
                "vector_store_size_mismatch index=%d manifest=%d", index.ntotal, len(chunks)
            )
            return False

        self._index = index
        self._chunks = chunks
        self._document_ids = {chunk.document_id for chunk in chunks}
        return True


def create_vector_store(kind: str) -> VectorStore:
    """Instantiate the requested store, degrading gracefully when FAISS is absent."""
    if kind == "faiss":
        try:
            return FaissVectorStore()
        except ImportError:
            logger.warning("faiss_unavailable falling_back_to=memory")
            return InMemoryVectorStore()
    if kind == "memory":
        return InMemoryVectorStore()
    raise ValueError(f"unknown vector store {kind!r}")
