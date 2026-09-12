"""The RBAC enforcement tests for retrieval.

These are the tests that matter most in Phase 2: an employee must not be able to
obtain restricted content, restricted chunk metadata, or even evidence that a
restricted document matched their query.
"""

from __future__ import annotations

import pytest

from app.core.enums import Role
from app.rag.documents import Chunk, DocumentValidationError
from app.rag.loader import build_documents, load_documents
from app.security.rbac import (
    authorized_document_ids,
    can_access_document,
    describe_role,
    filter_authorized,
    permits,
)

pytestmark = pytest.mark.security

#: Documents that only the security team may read, per the knowledge base.
SECURITY_ONLY = {"KB-003", "KB-004"}
#: Documents the IT service desk may read but employees may not.
IT_ONLY = {"KB-005", "KB-008", "KB-009"}
#: Everything else is visible to all roles.
EMPLOYEE_VISIBLE = {
    "KB-001",
    "KB-002",
    "KB-006",
    "KB-007",
    "KB-010",
    "KB-011",
    "KB-012",
}

#: A spread of queries, including ones that strongly match restricted documents.
PROBE_QUERIES = [
    "What are the password requirements?",
    "I received a phishing email and entered my password",
    "How do we investigate a phishing campaign?",
    "My computer is infected with ransomware, what do I do?",
    "I opened an attachment and now see strange pop-ups",
    "How do we classify incident severity?",
    "What is the joiner mover leaver process?",
    "How do we troubleshoot VPN connectivity?",
    "Show me the incident severity classification table",
    "What is the retention period for incident evidence?",
    "service account password rotation for privileged accounts",
    "command and control beaconing detection",
]


class TestDocumentPolicy:
    def test_employee_cannot_access_security_only_document(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        by_id = {document.document_id: document for document in documents}
        for document_id in SECURITY_ONLY:
            assert can_access_document(Role.EMPLOYEE, by_id[document_id].allowed_roles) is False
            assert can_access_document(Role.IT, by_id[document_id].allowed_roles) is False
            assert can_access_document(Role.SECURITY, by_id[document_id].allowed_roles) is True

    def test_employee_cannot_access_it_only_document(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        by_id = {document.document_id: document for document in documents}
        for document_id in IT_ONLY:
            assert can_access_document(Role.EMPLOYEE, by_id[document_id].allowed_roles) is False
            assert can_access_document(Role.IT, by_id[document_id].allowed_roles) is True

    def test_empty_audience_denies_everyone(self) -> None:
        """Fail closed: a document with no audience is readable by nobody."""
        for role in Role:
            assert can_access_document(role, frozenset()) is False

    def test_security_role_reaches_every_shipped_document(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        allowed = authorized_document_ids(documents, Role.SECURITY)
        assert allowed == {document.document_id for document in documents}

    def test_role_scopes_are_nested(self, kb_dir) -> None:
        """Employee scope must be a strict subset of IT, which is a subset of Security."""
        documents, _ = load_documents(kb_dir)
        employee = authorized_document_ids(documents, Role.EMPLOYEE)
        it_support = authorized_document_ids(documents, Role.IT)
        security = authorized_document_ids(documents, Role.SECURITY)
        assert employee < it_support < security

    def test_shipped_document_audiences_match_the_documented_matrix(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        employee = authorized_document_ids(documents, Role.EMPLOYEE)
        it_support = authorized_document_ids(documents, Role.IT)
        assert employee == EMPLOYEE_VISIBLE
        assert it_support == EMPLOYEE_VISIBLE | IT_ONLY

    def test_filter_authorized_preserves_order(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        filtered = filter_authorized(documents, Role.EMPLOYEE)
        assert [document.document_id for document in filtered] == [
            document.document_id
            for document in documents
            if document.document_id in EMPLOYEE_VISIBLE
        ]

    def test_chunk_inherits_document_audience(self, kb_dir) -> None:
        from app.rag.chunking import chunk_documents

        documents, _ = load_documents(kb_dir)
        chunks = chunk_documents(documents)
        by_id = {document.document_id: document for document in documents}
        for chunk in chunks:
            assert chunk.allowed_roles == by_id[chunk.document_id].allowed_roles

    def test_describe_role_reports_only_reachable_documents(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        description = describe_role(Role.EMPLOYEE, documents)
        assert set(description["document_ids"]) == EMPLOYEE_VISIBLE
        assert description["document_count"] == len(EMPLOYEE_VISIBLE)


class TestRetrievalIsolation:
    """The retrieval path itself must never surface restricted content."""

    @pytest.mark.parametrize("query", PROBE_QUERIES)
    def test_employee_retrieval_never_returns_restricted_documents(
        self, knowledge, query: str
    ) -> None:
        result = knowledge.search(query, role=Role.EMPLOYEE)
        returned = {match.chunk.document_id for match in result.matches}
        assert returned <= EMPLOYEE_VISIBLE, f"leaked {returned - EMPLOYEE_VISIBLE} for {query!r}"

    @pytest.mark.parametrize("query", PROBE_QUERIES)
    def test_it_retrieval_never_returns_security_only_documents(
        self, knowledge, query: str
    ) -> None:
        result = knowledge.search(query, role=Role.IT)
        returned = {match.chunk.document_id for match in result.matches}
        assert returned <= EMPLOYEE_VISIBLE | IT_ONLY

    @pytest.mark.parametrize("query", PROBE_QUERIES)
    def test_scores_are_independent_of_the_caller_role(self, knowledge, query: str) -> None:
        """Authorization must not influence scoring.

        This is the precise property that rules out an inference channel: the
        score of a chunk must depend only on (query, chunk), never on who is
        asking. The expected scores are computed here independently, over every
        chunk in the index, with no store and no top-k limit - so a bug that
        filtered *after* ranking, or that let restricted vectors influence the
        query, would change the numbers.
        """
        from app.rag.embeddings import cosine_similarity

        index = knowledge.index
        embedder = index.embedder
        query_vector = embedder.embed_query(query)
        all_vectors = embedder.embed([chunk.searchable_text() for chunk in index.chunks])
        expected = {
            chunk.chunk_id: cosine_similarity(query_vector, vector)
            for chunk, vector in zip(index.chunks, all_vectors, strict=True)
        }

        result = knowledge.search(query, role=Role.EMPLOYEE)
        assert result.matches, "an employee should reach at least one chunk for this query"
        for match in result.matches:
            assert match.score == pytest.approx(expected[match.chunk.chunk_id])

    def test_employee_top_result_equals_the_best_authorized_chunk(self, knowledge) -> None:
        """The best chunk an employee gets is the best chunk they are allowed.

        A post-filter implementation would return a *different* (lower) top
        result here, because the global winner would have been dropped.
        """
        from app.rag.embeddings import cosine_similarity

        index = knowledge.index
        allowed = index.authorized_document_ids(Role.EMPLOYEE)
        query = "How do we investigate a phishing campaign and handle credentials?"
        query_vector = index.embedder.embed_query(query)

        best_authorized = max(
            (
                cosine_similarity(query_vector, index.embedder.embed([chunk.searchable_text()])[0]),
                chunk.chunk_id,
            )
            for chunk in index.chunks
            if chunk.document_id in allowed
        )
        result = knowledge.search(query, role=Role.EMPLOYEE)
        assert result.matches
        assert result.matches[0].chunk.chunk_id == best_authorized[1]

    def test_restricted_document_is_excluded_even_when_it_is_the_best_match(
        self, knowledge
    ) -> None:
        """A query aimed squarely at a security-only document returns nothing."""
        query = "retention period for phishing investigation evidence case folder"
        employee = knowledge.search(query, role=Role.EMPLOYEE)
        security = knowledge.search(query, role=Role.SECURITY)
        assert all(m.chunk.document_id not in SECURITY_ONLY for m in employee.matches)
        # The security team is allowed to reach it, proving the document exists
        # and simply is not reachable by the employee.
        assert any(m.chunk.document_id in SECURITY_ONLY for m in security.matches)

    def test_employee_cannot_read_restricted_document_by_id(self, knowledge) -> None:
        for document_id in SECURITY_ONLY | IT_ONLY:
            assert knowledge.document_for(Role.EMPLOYEE, document_id) is None

    def test_document_listing_is_scoped(self, knowledge) -> None:
        assert {d["document_id"] for d in knowledge.documents_for(Role.EMPLOYEE)} == (
            EMPLOYEE_VISIBLE
        )

    def test_context_never_contains_restricted_content(self, knowledge, kb_dir) -> None:
        """No restricted *content* may appear in the context an employee's answer
        is built from.

        The restricted phrases are derived from the knowledge base rather than
        hardcoded: a phrase counts as restricted when it occurs in a document the
        employee cannot read and in **no** document the employee can read. That
        keeps the test correct as the knowledge base evolves.

        Note that a restricted document's *title* is allowed to appear: an
        employee-visible procedure may legitimately say "see the Malware Incident
        Response SOP, handled by the security team". Pointing at a restricted
        process is not disclosing its contents, and it is useful to the reader.
        """
        documents, _ = load_documents(kb_dir)
        employee_visible = [
            document for document in documents if document.document_id in EMPLOYEE_VISIBLE
        ]
        restricted = [
            document for document in documents if document.document_id not in EMPLOYEE_VISIBLE
        ]
        assert restricted, "the fixture expects some restricted documents"

        visible_text = " ".join(document.content.lower() for document in employee_visible)
        plain = lambda text: " ".join(text.lower().split())  # noqa: E731
        visible_flat = plain(visible_text)

        restricted_phrases: set[str] = set()
        for document in restricted:
            words = plain(document.content).split()
            for index in range(len(words) - 11):
                shingle = " ".join(words[index : index + 12])
                if shingle not in visible_flat:
                    restricted_phrases.add(shingle)

        assert len(restricted_phrases) > 50, "expected distinctive restricted content"

        for query in PROBE_QUERIES:
            result = knowledge.search(query, role=Role.EMPLOYEE)
            context = plain(result.context(max_chars=100_000))
            for document_id in sorted({d.document_id for d in restricted}):
                assert document_id not in context, f"{document_id} leaked for {query!r}"
            for phrase in restricted_phrases:
                assert phrase not in context, f"restricted text leaked for {query!r}: {phrase!r}"

    def test_context_blocks_are_labelled_for_citation(self, knowledge) -> None:
        result = knowledge.search("what are the password requirements", role=Role.EMPLOYEE)
        context = result.context(max_chars=100_000)
        assert "[1]" in context
        assert "KB-001" in context

    def test_context_respects_the_character_budget(self, knowledge) -> None:
        result = knowledge.search("security policy", role=Role.SECURITY)
        assert len(result.context(max_chars=400)) <= 400

    def test_empty_result_produces_empty_context(self, knowledge) -> None:
        result = knowledge.search("zzzz qqqq xxxx", role=Role.EMPLOYEE)
        assert result.matches == ()
        assert result.context(max_chars=1000) == ""
        assert result.sources == []

    def test_withheld_document_count_is_audit_only(self, knowledge) -> None:
        result = knowledge.search("incident severity", role=Role.EMPLOYEE)
        detail = result.audit_detail()
        assert detail["withheld_documents"] > 0
        # The user-facing citation payload must not expose that counter.
        for reference in result.sources:
            assert "withheld_documents" not in reference
            assert set(reference) == {
                "document_id",
                "title",
                "category",
                "section",
                "score",
                "snippet",
            }


class TestVectorStorePreFilter:
    """The vector store must refuse to search without an allow-list."""

    def test_search_requires_allowed_document_ids_keyword(self, knowledge) -> None:
        import inspect

        from app.rag.vector_store import InMemoryVectorStore

        signature = inspect.signature(InMemoryVectorStore.search)
        parameter = signature.parameters["allowed_document_ids"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty

    def test_empty_allow_list_returns_nothing(self, knowledge) -> None:
        store = knowledge.index.store
        query = knowledge.index.embedder.embed_query("password policy")
        assert store.search(query, top_k=5, allowed_document_ids=set()) == []

    def test_allow_list_restricts_results(self, knowledge) -> None:
        store = knowledge.index.store
        query = knowledge.index.embedder.embed_query("incident severity classification")
        restricted = store.search(query, top_k=5, allowed_document_ids={"KB-009"})
        assert restricted
        assert {match.chunk.document_id for match in restricted} == {"KB-009"}

    def test_unauthorized_chunk_is_dropped_by_the_retriever_defence_in_depth(
        self, knowledge
    ) -> None:
        """Even if a store returned an out-of-scope chunk, the retriever drops it."""
        from app.rag.retriever import Retriever

        class LeakyStore:
            """A deliberately broken store that ignores the allow-list."""

            name = "leaky"
            size = 1

            def __init__(self, chunk: Chunk) -> None:
                self._chunk = chunk

            def build(self, *args, **kwargs) -> None:  # pragma: no cover - protocol
                return None

            def save(self, *args, **kwargs) -> None:  # pragma: no cover - protocol
                return None

            def load(self, *args, **kwargs) -> bool:  # pragma: no cover - protocol
                return False

            def document_ids(self) -> set[str]:  # pragma: no cover - protocol
                return {self._chunk.document_id}

            def search(self, query_vector, *, top_k, allowed_document_ids):
                from app.rag.documents import ScoredChunk

                return [ScoredChunk(chunk=self._chunk, score=0.99)]

        restricted = next(
            chunk for chunk in knowledge.index.chunks if chunk.document_id in SECURITY_ONLY
        )
        index = knowledge.index
        index._store = LeakyStore(restricted)

        result = Retriever(index, index.settings).retrieve("anything", role=Role.EMPLOYEE)
        assert result.matches == ()
        assert result.dropped_unauthorized == 1


class TestMetadataCannotWidenAccess:
    """A metadata mistake must never enlarge an audience."""

    def test_missing_allowed_roles_is_rejected(self) -> None:
        with pytest.raises(DocumentValidationError, match="allowed_roles"):
            build_documents(
                [
                    {
                        "document_id": "KB-900",
                        "title": "No audience",
                        "category": "policy",
                        "content": "x" * 300,
                    }
                ]
            )

    def test_empty_allowed_roles_is_rejected(self) -> None:
        with pytest.raises(DocumentValidationError, match="must not be empty"):
            build_documents(
                [
                    {
                        "document_id": "KB-901",
                        "title": "Empty audience",
                        "category": "policy",
                        "allowed_roles": [],
                        "content": "x" * 300,
                    }
                ]
            )

    def test_misspelled_key_is_rejected_rather_than_ignored(self) -> None:
        """`allow_roles` must not silently behave like "no restriction"."""
        with pytest.raises(DocumentValidationError, match="unknown front matter key"):
            build_documents(
                [
                    {
                        "document_id": "KB-902",
                        "title": "Typo",
                        "category": "policy",
                        "allow_roles": ["employee"],
                        "content": "x" * 300,
                    }
                ]
            )

    def test_unknown_role_is_rejected(self) -> None:
        with pytest.raises(DocumentValidationError, match="unknown role"):
            build_documents(
                [
                    {
                        "document_id": "KB-903",
                        "title": "Bad role",
                        "category": "policy",
                        "allowed_roles": ["admin"],
                        "content": "x" * 300,
                    }
                ]
            )

    def test_default_role_is_never_implied(self) -> None:
        """A well-formed document grants exactly the roles it declares."""
        documents = build_documents(
            [
                {
                    "document_id": "KB-904",
                    "title": "Security only",
                    "category": "policy",
                    "allowed_roles": ["security"],
                    "content": "Restricted body text. " * 20,
                }
            ]
        )
        document = documents[0]
        assert document.permits(Role.SECURITY)
        assert not document.permits(Role.IT)
        assert not document.permits(Role.EMPLOYEE)
        assert not permits(document, Role.EMPLOYEE)
