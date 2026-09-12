"""Knowledge index: loads documents, chunks them, embeds them and exposes
authorisation-filtered retrieval.

Freshness model
---------------
Documents and chunks are **always** read from the knowledge base directory at
startup, so permission metadata can never be stale. Only the *vectors* are
cached on disk, together with a fingerprint of the source content; when the
fingerprint changes the vectors are recomputed. A cache hit therefore never
serves an authorisation decision made against an older version of a document.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import threading
from collections.abc import Sequence
from pathlib import Path

from app.core.config import Settings, get_settings
from app.core.enums import Role
from app.rag.chunking import CHUNKER_VERSION, ChunkingConfig, chunk_documents
from app.rag.documents import Chunk, KnowledgeDocument
from app.rag.embeddings import TOKENIZER_VERSION, EmbeddingProvider, get_embedding_provider
from app.rag.loader import load_documents, summarise_audience
from app.rag.vector_store import VectorStore, create_vector_store
from app.security.rbac import authorized_document_ids, filter_authorized

logger = logging.getLogger(__name__)

FINGERPRINT_FILE = "fingerprint.txt"
EMBEDDING_STATE_FILE = "embedding_state.json"


@dataclasses.dataclass(frozen=True, slots=True)
class IndexStats:
    """Observable facts about the built index."""

    document_count: int
    chunk_count: int
    embedding_dimension: int
    vector_store: str
    embedding_provider: str
    documents_per_role: dict[str, int]
    fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


def compute_fingerprint(
    documents: Sequence[KnowledgeDocument],
    *,
    config_fingerprint: str = "",
) -> str:
    """Stable hash of the knowledge base content, its permissions and the index
    configuration.

    Both the body text *and* ``allowed_roles`` are included, so a change to who
    may read a document invalidates the cached vectors just as a content edit
    does. ``config_fingerprint`` covers chunking, embedding and tokenizer
    settings: vectors produced with a different chunk size or tokenizer are not
    comparable, and silently reusing them would degrade every answer with no
    visible error.
    """
    digest = hashlib.sha256()
    digest.update(config_fingerprint.encode("utf-8"))
    digest.update(b"\x1f")
    for document in sorted(documents, key=lambda item: item.document_id):
        digest.update(document.document_id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(
            ",".join(sorted(role.value for role in document.allowed_roles)).encode("utf-8")
        )
        digest.update(b"\x00")
        digest.update(document.content.encode("utf-8"))
        digest.update(b"\x1e")
    return digest.hexdigest()


class KnowledgeIndex:
    """In-process index over the knowledge base."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        embedder: EmbeddingProvider | None = None,
        store: VectorStore | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._embedder = embedder or get_embedding_provider(self._settings)
        self._store = store or create_vector_store(self._settings.vector_store)
        self._documents: list[KnowledgeDocument] = []
        self._chunks: list[Chunk] = []
        self._stats = IndexStats(
            0, 0, self._embedder.dimension, self._store.name, self._embedder.name, {}, ""
        )
        self._built = False
        self._lock = threading.RLock()

    # -- properties -------------------------------------------------------
    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def documents(self) -> list[KnowledgeDocument]:
        return self._documents

    @property
    def chunks(self) -> list[Chunk]:
        return self._chunks

    @property
    def store(self) -> VectorStore:
        return self._store

    @property
    def embedder(self) -> EmbeddingProvider:
        return self._embedder

    @property
    def stats(self) -> IndexStats:
        return self._stats

    @property
    def is_built(self) -> bool:
        return self._built

    @property
    def index_directory(self) -> Path:
        return self._settings.vector_store_dir

    # -- building ---------------------------------------------------------
    def _chunking_config(self) -> ChunkingConfig:
        return ChunkingConfig(
            max_chars=self._settings.rag_chunk_max_chars,
            overlap_chars=self._settings.rag_chunk_overlap_chars,
        )

    def _config_fingerprint(self) -> str:
        """Identify the vectorisation configuration behind a cached index."""
        host = getattr(self._embedder, "host", None)
        return ":".join(
            [
                self._embedder.name,
                str(self._embedder.dimension),
                TOKENIZER_VERSION,
                # The chunker *version* as well as its settings: the size
                # parameters alone do not change when the algorithm does, so a
                # cached index would otherwise keep chunks the current code would
                # never produce.
                CHUNKER_VERSION,
                str(self._settings.rag_chunk_max_chars),
                str(self._settings.rag_chunk_overlap_chars),
                self._store.name,
                str(host if host is not None else ""),
            ]
        )

    def build(self, *, use_cache: bool = True) -> IndexStats:
        """Load, chunk, embed and index the knowledge base.

        Called at startup. Never raises for an empty knowledge base: the
        assistant should report "no knowledge available" rather than fail to
        start, but a *malformed* document does raise under strict validation.
        """
        with self._lock:
            kb_dir = self._settings.knowledge_base_dir
            documents, errors = load_documents(kb_dir, strict=self._settings.kb_strict_validation)
            if errors:  # pragma: no cover - only reachable in non-strict mode
                logger.warning("knowledge_base_partial errors=%d", len(errors))

            self._documents = list(documents)
            self._chunks = chunk_documents(self._documents, self._chunking_config())
            fingerprint = compute_fingerprint(
                self._documents, config_fingerprint=self._config_fingerprint()
            )

            loaded = False
            if use_cache and self._chunks:
                loaded = self._load_cached_vectors(fingerprint)

            if not loaded:
                # A lexical provider must see the whole corpus before it can
                # weight terms; a hosted provider needs no fitting step. The
                # corpus is the *searchable* representation (title + section +
                # body), which is what gets embedded and scored.
                searchable = [chunk.searchable_text() for chunk in self._chunks]
                if not self._embedder.is_fitted:
                    self._embedder.fit(searchable)
                if searchable:
                    vectors = self._embedder.embed(searchable)
                    self._store.build(self._chunks, vectors)
                else:
                    self._store.build([], [])
                self._save_cached_vectors(fingerprint)

            self._stats = IndexStats(
                document_count=len(self._documents),
                chunk_count=len(self._chunks) if (loaded or self._store.size) else 0,
                embedding_dimension=self._embedder.dimension,
                vector_store=self._store.name,
                embedding_provider=self._embedder.name,
                documents_per_role=summarise_audience(self._documents),
                fingerprint=fingerprint,
            )
            self._built = True
            logger.info(
                "index_built documents=%d chunks=%d store=%s cache_hit=%s",
                self._stats.document_count,
                self._stats.chunk_count,
                self._stats.vector_store,
                loaded,
            )
            return self._stats

    def _load_cached_vectors(self, fingerprint: str) -> bool:
        directory = self.index_directory
        marker = directory / FINGERPRINT_FILE
        try:
            if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != fingerprint:
                return False
            # The provider state must be restored *before* the store loads, so a
            # query is embedded with exactly the weights the chunks were built
            # with. Mismatched weights would silently degrade every answer.
            state_path = directory / EMBEDDING_STATE_FILE
            if not state_path.is_file():
                return False
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if not self._embedder.load_state(state):
                logger.info("index_cache_stale reason=embedding_state")
                return False
            if not self._store.load(directory):
                return False
        except (OSError, json.JSONDecodeError):
            return False

        # The cache must describe exactly the chunks we just derived from disk.
        if self._store.size != len(self._chunks):
            logger.info("index_cache_stale reason=size_mismatch")
            return False
        return True

    def _save_cached_vectors(self, fingerprint: str) -> None:
        directory = self.index_directory
        try:
            directory.mkdir(parents=True, exist_ok=True)
            self._store.save(directory)
            state = self._embedder.state()
            if state is not None:
                (directory / EMBEDDING_STATE_FILE).write_text(
                    json.dumps(state, ensure_ascii=False), encoding="utf-8"
                )
            (directory / FINGERPRINT_FILE).write_text(fingerprint, encoding="utf-8")
        except OSError:  # pragma: no cover - cache write is best effort
            logger.warning("index_cache_write_failed path=%s", directory, exc_info=True)

    def refresh(self) -> IndexStats:
        """Rebuild from disk, ignoring the vector cache."""
        with self._lock:
            self._store = create_vector_store(self._settings.vector_store)
            return self.build(use_cache=False)

    # -- authorisation + retrieval ---------------------------------------
    def authorized_document_ids(self, role: Role) -> frozenset[str]:
        """Document ids ``role`` may retrieve from.

        Computed from the freshly loaded document metadata, never from the
        vector store's contents.
        """
        return authorized_document_ids(self._documents, role)

    def documents_for(self, role: Role) -> list[KnowledgeDocument]:
        return filter_authorized(self._documents, role)

    def authorized_chunk_count(self, role: Role) -> int:
        allowed = self.authorized_document_ids(role)
        return sum(1 for chunk in self._chunks if chunk.document_id in allowed)
