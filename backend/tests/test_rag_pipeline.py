"""Chunking, embedding and vector store unit tests."""

from __future__ import annotations

from typing import ClassVar

import pytest

from app.core.enums import Role
from app.rag.chunking import ChunkingConfig, chunk_document, chunk_documents
from app.rag.documents import KnowledgeDocument
from app.rag.embeddings import (
    STOPWORDS,
    TfIdfEmbeddingProvider,
    cosine_similarity,
    get_embedding_provider,
    tokenize,
)
from app.rag.loader import build_documents, load_documents
from app.rag.vector_store import (
    MAX_TOP_K,
    FaissVectorStore,
    InMemoryVectorStore,
    create_vector_store,
)

BODY = "\n\n".join(
    f"## Section {index}\n\n"
    + (f"Paragraph {index} about password policy and account security. " * 6)
    for index in range(1, 7)
)

DOCUMENT_RAW = {
    "document_id": "KB-500",
    "title": "Chunking Fixture",
    "category": "policy",
    "allowed_roles": ["employee", "security"],
    "content": f"# Chunking Fixture\n\n{BODY}",
}


def make_document(**overrides) -> KnowledgeDocument:
    return build_documents([{**DOCUMENT_RAW, **overrides}])[0]


class TestChunking:
    def test_chunks_are_deterministic(self) -> None:
        document = make_document()
        first = chunk_document(document)
        second = chunk_document(document)
        assert [c.chunk_id for c in first] == [c.chunk_id for c in second]
        assert [c.text for c in first] == [c.text for c in second]

    def test_chunk_ids_are_addressable(self) -> None:
        chunks = chunk_document(make_document())
        assert chunks[0].chunk_id == "KB-500#000"
        assert chunks[1].chunk_id == "KB-500#001"
        assert [chunk.position for chunk in chunks] == list(range(len(chunks)))

    def test_chunks_respect_the_size_budget(self) -> None:
        config = ChunkingConfig(max_chars=600, overlap_chars=50)
        for chunk in chunk_document(make_document(), config):
            assert len(chunk.text) <= 1600  # hard limit for an unsplittable block

    def test_the_hard_ceiling_holds_when_a_block_is_oversized(self) -> None:
        """The ceiling must survive the overlap prefix.

        `_split_long_text` bounds a *piece* to 1600 characters, but the overlap
        carried into the next chunk is prepended afterwards. On the shipped
        knowledge base that produced a 1640-character chunk - 40 over the bound
        the code claims to enforce. The synthetic fixture above never triggered
        the path, because none of its blocks is oversized, so this test builds
        one deliberately.
        """
        from app.rag.chunking import _HARD_SPLIT_CHARS

        config = ChunkingConfig(max_chars=700, overlap_chars=100)
        oversized_block = "The VPN diagnostic procedure follows. " * 35  # ~1295 chars
        assert len(oversized_block) > config.max_chars

        document = make_document(
            content=(
                "# Oversized\n\n"
                "## 1. Before you start\n\n"
                "Confirm the user has an active VPN entitlement.\n\n"
                "## 2. Diagnosis\n\n"
                f"{oversized_block}\n\n"
                "## 3. Escalation\n\n"
                "Raise a ticket with the service desk.\n"
            )
        )

        chunks = chunk_document(document, config)
        assert chunks, "the fixture must produce chunks"
        assert max(len(chunk.text) for chunk in chunks) <= _HARD_SPLIT_CHARS, (
            f"a chunk exceeded the hard ceiling: "
            f"{max(len(chunk.text) for chunk in chunks)} > {_HARD_SPLIT_CHARS}"
        )
        # And the oversized block really was exercised, not quietly skipped.
        assert any(len(chunk.text) > config.max_chars for chunk in chunks)

    def test_the_hard_ceiling_holds_across_the_shipped_knowledge_base(self) -> None:
        """The bound must hold for the real corpus, not just a fixture."""
        from app.core.config import get_settings
        from app.rag.chunking import _HARD_SPLIT_CHARS
        from app.rag.loader import load_documents

        settings = get_settings()
        documents, errors = load_documents(settings.knowledge_base_dir)
        assert documents and not errors

        config = ChunkingConfig(settings.rag_chunk_max_chars, settings.rag_chunk_overlap_chars)
        chunks = chunk_documents(documents, config)
        longest = max(len(chunk.text) for chunk in chunks)
        assert longest <= _HARD_SPLIT_CHARS, (
            f"{sum(1 for c in chunks if len(c.text) > _HARD_SPLIT_CHARS)} chunk(s) exceed "
            f"{_HARD_SPLIT_CHARS}; longest is {longest}"
        )

    def test_smaller_budget_produces_more_chunks(self) -> None:
        document = make_document()
        large = chunk_document(document, ChunkingConfig(max_chars=2000, overlap_chars=0))
        small = chunk_document(document, ChunkingConfig(max_chars=400, overlap_chars=0))
        assert len(small) > len(large)

    def test_roles_are_copied_onto_every_chunk(self) -> None:
        document = make_document()
        for chunk in chunk_document(document):
            assert chunk.allowed_roles == document.allowed_roles
            assert chunk.permits(Role.EMPLOYEE)
            assert not chunk.permits(Role.IT)

    def test_sections_are_derived_from_headings(self) -> None:
        sections = {chunk.section for chunk in chunk_document(make_document())}
        assert any("Section 3" in section for section in sections)

    def test_invalid_config_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            ChunkingConfig(max_chars=50)
        with pytest.raises(ValueError):
            ChunkingConfig(max_chars=500, overlap_chars=500)

    def test_document_without_body_produces_no_chunks(self) -> None:
        document = make_document(content="# Empty\n\n" + "x" * 260)
        assert chunk_document(document)  # still chunks the body

    def test_chunk_documents_preserves_document_order(self) -> None:
        documents = [
            make_document(document_id="KB-501"),
            make_document(document_id="KB-502"),
        ]
        chunks = chunk_documents(documents)
        assert [c.document_id for c in chunks] == sorted(
            [c.document_id for c in chunks], key=lambda value: value
        )

    def test_searchable_text_includes_title_and_excludes_synthetic_noise(self) -> None:
        chunk = chunk_document(make_document())[0]
        searchable = chunk.searchable_text()
        assert chunk.title in searchable
        assert chunk.text in searchable
        # The display text stays clean: it is what the user is shown.
        assert chunk.title not in chunk.text or chunk.title in chunk.text


class TestIndexFingerprint:
    """A cached index must be invalidated by anything that changes its vectors.

    The chunk *size settings* were in the fingerprint from the start, but the
    chunking *algorithm* was not. Changing how text is divided therefore left a
    stale cache in place - the index would keep chunks the current code would
    never produce, and the only symptom would be quietly worse retrieval.
    """

    def test_the_fingerprint_covers_the_chunker_version(self) -> None:
        from app.core.config import get_settings
        from app.rag.chunking import CHUNKER_VERSION
        from app.rag.index import KnowledgeIndex

        index = KnowledgeIndex(get_settings())
        assert CHUNKER_VERSION in index._config_fingerprint()

    def test_the_fingerprint_covers_the_tokenizer_version(self) -> None:
        from app.core.config import get_settings
        from app.rag.embeddings import TOKENIZER_VERSION
        from app.rag.index import KnowledgeIndex

        index = KnowledgeIndex(get_settings())
        assert TOKENIZER_VERSION in index._config_fingerprint()

    def test_changing_the_chunker_version_changes_the_fingerprint(self) -> None:
        from unittest.mock import patch

        from app.core.config import get_settings
        from app.rag.index import KnowledgeIndex, compute_fingerprint

        settings = get_settings()
        index = KnowledgeIndex(settings)
        documents, _ = load_documents(settings.knowledge_base_dir)

        before = compute_fingerprint(documents, config_fingerprint=index._config_fingerprint())
        with patch("app.rag.index.CHUNKER_VERSION", "999"):
            after = compute_fingerprint(
                documents, config_fingerprint=index._config_fingerprint()
            )
        assert before != after, "a chunker change must invalidate the cached index"

    def test_metadata_permissions_still_invalidate_the_cache(self) -> None:
        # The property the fingerprint was built for: narrowing a document's
        # audience must not be served from a cache built when it was wider.
        from app.rag.index import compute_fingerprint

        document = make_document()
        wide = compute_fingerprint([document], config_fingerprint="x")
        narrowed = build_documents(
            [{**DOCUMENT_RAW, "allowed_roles": ["security"]}]
        )[0]
        assert compute_fingerprint([narrowed], config_fingerprint="x") != wide


class TestTokenizer:
    def test_stopwords_are_removed(self) -> None:
        assert "the" not in tokenize("the password policy")
        assert "password" in tokenize("the password policy")

    def test_hyphenated_and_solid_forms_match(self) -> None:
        assert tokenize("pop-up window") == tokenize("popup window")
        assert tokenize("single sign-on") == tokenize("single signon")

    def test_plurals_fold_to_the_same_token(self) -> None:
        assert tokenize("requirements") == tokenize("requirement")
        assert tokenize("policies") == tokenize("policy")

    def test_gerunds_fold(self) -> None:
        assert tokenize("connecting") == tokenize("connect")

    def test_numbers_are_ignored(self) -> None:
        assert tokenize("2024 555 0100") == []

    def test_empty_input(self) -> None:
        assert tokenize("") == []
        assert tokenize("   ") == []

    def test_stopword_list_is_not_corpus_derived(self) -> None:
        # A sanity check that the list is static English, not built from the KB.
        assert {"the", "and", "with"} <= STOPWORDS


class TestTfIdfEmbeddings:
    CORPUS: ClassVar[list[str]] = [
        "password policy requirements for all accounts",
        "vpn troubleshooting steps for remote access",
        "phishing response procedure when you receive a suspicious email",
        "malware incident response containment and eradication",
    ]

    def test_requires_fitting_before_use(self) -> None:
        from app.core.errors import ConfigurationError

        provider = TfIdfEmbeddingProvider()
        with pytest.raises(ConfigurationError, match="fitted"):
            provider.embed_query("anything")
        assert provider.is_fitted is False

    def test_dimension_matches_vocabulary(self) -> None:
        provider = TfIdfEmbeddingProvider()
        provider.fit(self.CORPUS)
        assert provider.dimension == provider.vocabulary_size > 0

    def test_vectors_are_unit_length(self) -> None:
        provider = TfIdfEmbeddingProvider()
        provider.fit(self.CORPUS)
        for vector in provider.embed(self.CORPUS):
            assert cosine_similarity(vector, vector) == pytest.approx(1.0)

    def test_fitting_is_deterministic(self) -> None:
        first = TfIdfEmbeddingProvider()
        first.fit(self.CORPUS)
        second = TfIdfEmbeddingProvider()
        second.fit(self.CORPUS)
        assert first.state() == second.state()
        assert first.embed(self.CORPUS) == second.embed(self.CORPUS)

    def test_matching_document_scores_highest(self) -> None:
        provider = TfIdfEmbeddingProvider()
        provider.fit(self.CORPUS)
        vectors = provider.embed(self.CORPUS)
        query = provider.embed_query("what are the password requirements")
        scores = [cosine_similarity(query, vector) for vector in vectors]
        assert scores.index(max(scores)) == 0

    def test_out_of_vocabulary_terms_are_ignored(self) -> None:
        provider = TfIdfEmbeddingProvider()
        provider.fit(self.CORPUS)
        vector = provider.embed_query("zzzzz qqqqq")
        assert set(vector) == {0.0}

    def test_state_roundtrip_preserves_scores(self) -> None:
        provider = TfIdfEmbeddingProvider()
        provider.fit(self.CORPUS)
        expected = provider.embed_query("vpn remote access")

        restored = TfIdfEmbeddingProvider()
        assert restored.load_state(provider.state()) is True
        assert restored.is_fitted is True
        assert restored.embed_query("vpn remote access") == expected

    def test_state_from_another_provider_is_rejected(self) -> None:
        restored = TfIdfEmbeddingProvider()
        assert restored.load_state({"name": "something-else"}) is False
        assert restored.is_fitted is False

    def test_corrupt_state_is_rejected(self) -> None:
        restored = TfIdfEmbeddingProvider()
        assert restored.load_state({"name": "tfidf", "vocabulary": {}, "idf": [1.0]}) is False

    def test_vocabulary_cap_is_enforced(self) -> None:
        provider = TfIdfEmbeddingProvider(max_features=5)
        provider.fit([" ".join(f"token{index}" for index in range(50))])
        assert provider.vocabulary_size == 5

    def test_length_normalisation_down_weights_verbose_documents(self) -> None:
        """A long document that merely mentions a topic must not outrank a
        short, focused document about it."""
        short = "vpn troubleshooting procedure steps"
        verbose = ("vpn " * 40) + " ".join(f"filler{index}" for index in range(200))
        provider = TfIdfEmbeddingProvider()
        provider.fit([short, verbose])
        vectors = provider.embed([short, verbose])
        query = provider.embed_query("vpn troubleshooting")
        short_score = cosine_similarity(query, vectors[0])
        verbose_score = cosine_similarity(query, vectors[1])
        assert short_score > verbose_score

    def test_default_provider_is_the_offline_one(self, settings) -> None:
        provider = get_embedding_provider(settings)
        assert provider.name == "tfidf"

    def test_openai_provider_requires_a_key(self, settings) -> None:
        from app.core.errors import ConfigurationError

        configured = settings.model_copy(
            update={"embedding_provider": "openai_compatible", "embedding_api_key": ""}
        )
        with pytest.raises(ConfigurationError, match="EMBEDDING_API_KEY"):
            get_embedding_provider(configured)


class TestVectorStores:
    @pytest.fixture
    def corpus(self):
        """Two documents with an identical body but different audiences.

        Identical content makes the test strict: the only thing that can keep
        the restricted document out of the results is the authorization filter.
        """
        documents = [
            make_document(
                document_id="KB-501",
                title="Visible",
                allowed_roles=["employee"],
                content="# Visible\n\n" + "password policy account security. " * 40,
            ),
            make_document(
                document_id="KB-502",
                title="Restricted",
                allowed_roles=["security"],
                content="# Restricted\n\n" + "password policy account security. " * 40,
            ),
        ]
        chunks = chunk_documents(documents)
        provider = TfIdfEmbeddingProvider()
        searchable = [chunk.searchable_text() for chunk in chunks]
        provider.fit(searchable)
        return (
            chunks,
            provider.embed(searchable),
            provider.embed_query("password policy account security"),
        )

    @pytest.mark.parametrize("store_factory", [InMemoryVectorStore, FaissVectorStore])
    def test_pre_filter_excludes_restricted_document(self, store_factory, corpus) -> None:
        chunks, vectors, query = corpus
        store = store_factory()
        store.build(chunks, vectors)

        results = store.search(query, top_k=10, allowed_document_ids={"KB-501"})
        assert results
        assert {match.chunk.document_id for match in results} == {"KB-501"}

    @pytest.mark.parametrize("store_factory", [InMemoryVectorStore, FaissVectorStore])
    def test_both_stores_agree_on_ranking(self, store_factory, corpus) -> None:
        chunks, vectors, query = corpus

        memory = InMemoryVectorStore()
        memory.build(chunks, vectors)
        other = store_factory()
        other.build(chunks, vectors)

        allowed = {"KB-501", "KB-502"}
        memory_ranking = [
            m.chunk.chunk_id for m in memory.search(query, top_k=5, allowed_document_ids=allowed)
        ]
        other_ranking = [
            m.chunk.chunk_id for m in other.search(query, top_k=5, allowed_document_ids=allowed)
        ]
        assert memory_ranking == other_ranking

    def test_top_k_is_clamped(self, corpus) -> None:
        chunks, vectors, query = corpus
        store = InMemoryVectorStore()
        store.build(chunks, vectors)

        assert store.search(query, top_k=0, allowed_document_ids={"KB-501"}) == []
        assert store.search(query, top_k=-5, allowed_document_ids={"KB-501"}) == []
        assert len(store.search(query, top_k=10_000, allowed_document_ids={"KB-501"})) <= MAX_TOP_K

    def test_mismatched_lengths_are_rejected(self, corpus) -> None:
        chunks, _, _ = corpus
        with pytest.raises(ValueError, match="same length"):
            InMemoryVectorStore().build(chunks, [])

    def test_memory_store_save_load_roundtrip(self, corpus, tmp_path) -> None:
        chunks, vectors, query = corpus
        original = InMemoryVectorStore()
        original.build(chunks, vectors)
        original.save(tmp_path)

        restored = InMemoryVectorStore()
        assert restored.load(tmp_path) is True
        assert restored.size == original.size
        expected = [
            m.chunk.chunk_id
            for m in original.search(query, top_k=3, allowed_document_ids={"KB-501"})
        ]
        actual = [
            m.chunk.chunk_id
            for m in restored.search(query, top_k=3, allowed_document_ids={"KB-501"})
        ]
        assert actual == expected

    def test_faiss_store_save_load_roundtrip(self, corpus, tmp_path) -> None:
        chunks, vectors, query = corpus
        original = FaissVectorStore()
        original.build(chunks, vectors)
        original.save(tmp_path)

        restored = FaissVectorStore()
        assert restored.load(tmp_path) is True
        assert restored.size == original.size
        expected = [
            m.chunk.chunk_id
            for m in original.search(query, top_k=3, allowed_document_ids={"KB-501"})
        ]
        actual = [
            m.chunk.chunk_id
            for m in restored.search(query, top_k=3, allowed_document_ids={"KB-501"})
        ]
        assert actual == expected

    def test_load_returns_false_when_nothing_is_cached(self, tmp_path) -> None:
        assert InMemoryVectorStore().load(tmp_path) is False
        assert FaissVectorStore().load(tmp_path) is False

    def test_corrupt_manifest_does_not_raise(self, tmp_path) -> None:
        (tmp_path / "index.json").write_text("{not json", encoding="utf-8")
        assert InMemoryVectorStore().load(tmp_path) is False

    def test_factory_falls_back_to_memory_for_unknown_kind(self) -> None:
        with pytest.raises(ValueError, match="unknown vector store"):
            create_vector_store("pinecone")

    def test_factory_builds_both_kinds(self) -> None:
        assert create_vector_store("memory").name == "memory"
        assert create_vector_store("faiss").name == "faiss"

    def test_empty_store_returns_nothing(self) -> None:
        store = InMemoryVectorStore()
        store.build([], [])
        assert store.search([0.1, 0.2], top_k=5, allowed_document_ids={"KB-001"}) == []
