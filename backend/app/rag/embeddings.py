"""Embedding providers.

Two providers ship with the platform.

``tfidf`` (default, offline)
    A fitted TF-IDF vector-space model. It needs no API key, no model download
    and no network, so the whole RAG pipeline is reproducible in tests and in an
    air-gapped demo. It is a **lexical** model: it ranks by weighted term
    overlap, not by meaning. It is honest about that, and the pipeline is
    designed so it can be replaced without touching anything else.

``openai_compatible``
    Real semantic embeddings from any OpenAI-compatible ``/embeddings``
    endpoint. Set ``EMBEDDING_PROVIDER=openai_compatible`` and supply
    ``EMBEDDING_API_KEY``; nothing else in the retriever changes.

Both satisfy :class:`EmbeddingProvider`. The TF-IDF provider must be *fitted*
on the corpus before it can embed a query, exactly like a scikit-learn
vectorizer; its state is persisted next to the vector index so a restart reuses
identical weights.

Determinism: the same corpus and the same text always produce the same vector,
and the tokenizer never uses Python's salted ``hash()``.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any, Protocol

import snowballstemmer

from app.core.config import Settings, get_settings
from app.core.errors import ConfigurationError, UpstreamServiceError

logger = logging.getLogger(__name__)

#: Bump when tokenisation, weighting or the stopword list changes. The value is
#: folded into the index fingerprint so a cached vector index built by an older
#: tokenizer is never reused: vectors from two different tokenizers are not
#: comparable, and reusing them would silently degrade every answer.
TOKENIZER_VERSION = "2"

#: Common English words carry little signal and add noise. This is a static
#: linguistic list - it is not derived from the knowledge base.
#:
#: Function words matter more than they appear to: in a TF-IDF space, a rare
#: function word that escaped the list gets a maximal IDF and can dominate a
#: query on its own. "What else should I know?" retrieved the wrong document
#: entirely because "else" happened to occur in exactly one chunk.
STOPWORDS = frozenset(
    """
    a about above after again against all am an and any are aren as at be because
    been before being below between both but by can cannot could couldn did do
    does doesn doing don down during each few for from further had hadn has hasn
    have haven having he her here hers herself him himself his how i if in into
    is isn it its itself just me more most mustn my myself no nor not now of off
    on once only or other ought our ours ourselves out over own same shan she
    should shouldn so some such than that the their theirs them themselves then
    there these they this those through to too under until up very was wasn we
    were weren what when where which while who whom why will with won would
    wouldn you your yours yourself yourselves
    please tell need want know get
    else otherwise instead however therefore thus hence regarding concerning
    another others whatever whenever whoever anymore
    """.split()
)

_TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{1,}")
_NUMBER_RE = re.compile(r"^\d+$")

#: Snowball (Porter2) English stemmer. A real stemmer rather than hand-rolled
#: suffix rules, because consistent conflation is what lexical retrieval depends
#: on: a user types "cannot connect" while the knowledge base says "connection
#: failure", and those must reduce to the same term.
_STEMMER = snowballstemmer.stemmer("english")


def _normalise_token(token: str) -> str:
    return _STEMMER.stemWord(token)


def tokenize(text: str) -> list[str]:
    """Lowercase content tokens with stopwords removed and light normalisation.

    Hyphens are removed rather than treated as separators, so "pop-up" and
    "popup", or "sign-on" and "signon", produce the same token. The knowledge
    base uses hyphenated spellings while users type them solid (or the other way
    round), and treating the two forms as different words silently loses
    matches.
    """
    tokens: list[str] = []
    for raw in _TOKEN_RE.findall(text.lower().replace("-", "").replace("'", "")):
        if _NUMBER_RE.match(raw) or raw in STOPWORDS:
            continue
        token = _normalise_token(raw)
        if len(token) < 2 or token in STOPWORDS:
            continue
        tokens.append(token)
    return tokens


class EmbeddingProvider(Protocol):
    """Vectorises text. Implementations may need to be fitted first."""

    @property
    def name(self) -> str: ...

    @property
    def dimension(self) -> int: ...

    @property
    def is_fitted(self) -> bool: ...

    def fit(self, corpus: Sequence[str]) -> None: ...

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...

    def state(self) -> dict[str, Any] | None: ...

    def load_state(self, state: dict[str, Any]) -> bool: ...


def _l2_normalise(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        return vector
    return [value / norm for value in vector]


class TfIdfEmbeddingProvider:
    """TF-IDF vector-space model with BM25 term weighting.

    Plain TF-IDF ranks badly on this corpus for a specific and predictable
    reason: a long policy document that merely *mentions* a topic accumulates
    term frequency for it and outranks the short procedure that actually answers
    the question. Two standard corrections fix that:

    * **saturation** (``k1``) - the tenth occurrence of a term adds almost
      nothing over the second;
    * **length normalisation** (``b``) - a term in a chunk twice the average
      length counts for less.

        w(t, d) = idf(t) * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * len_d / avg_len))
        idf(t)  = ln((1 + N) / (1 + df(t))) + 1

    Vectors are L2-normalised, so cosine similarity is a plain dot product and
    FAISS ``IndexFlatIP`` can be used directly.
    """

    #: Standard BM25 parameters. ``k1`` controls term saturation, ``b`` the
    #: strength of length normalisation.
    K1 = 1.2
    B = 0.75

    def __init__(self, max_features: int = 20000) -> None:
        self._vocabulary: dict[str, int] = {}
        self._idf: list[float] = []
        self._average_length: float = 1.0
        self._fitted = False
        self._max_features = max_features

    @property
    def name(self) -> str:
        return "tfidf"

    @property
    def dimension(self) -> int:
        return len(self._vocabulary)

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    @property
    def vocabulary_size(self) -> int:
        return len(self._vocabulary)

    @property
    def average_document_length(self) -> float:
        return self._average_length

    def fit(self, corpus: Sequence[str]) -> None:
        """Build the vocabulary, IDF weights and average length from the corpus."""
        document_frequency: Counter[str] = Counter()
        total_frequency: Counter[str] = Counter()
        total_length = 0

        for text in corpus:
            counts = Counter(tokenize(text))
            total_length += sum(counts.values())
            document_frequency.update(counts.keys())
            total_frequency.update(counts)

        terms = list(document_frequency)
        if len(terms) > self._max_features:
            # Safety valve for a pathologically large corpus: keep the terms with
            # the highest total frequency, which are the ones most queries use.
            logger.warning(
                "tfidf_vocabulary_capped total=%d max=%d", len(terms), self._max_features
            )
            terms = [term for term, _ in total_frequency.most_common(self._max_features)]

        # Deterministic index assignment: frequent terms first, ties broken by
        # term, so the vocabulary (and every vector) is stable across runs.
        terms.sort(key=lambda term: (-total_frequency[term], term))
        self._vocabulary = {term: index for index, term in enumerate(terms)}

        total_documents = max(1, len(corpus))
        idf = [0.0] * len(self._vocabulary)
        for term, index in self._vocabulary.items():
            idf[index] = math.log((1 + total_documents) / (1 + document_frequency[term])) + 1.0
        self._idf = idf
        self._average_length = max(1.0, total_length / max(1, len(corpus)))
        self._fitted = True
        logger.info(
            "tfidf_fitted documents=%d vocabulary=%d avg_length=%.1f",
            total_documents,
            len(self._vocabulary),
            self._average_length,
        )

    def _weigh_document(self, text: str) -> list[float]:
        """BM25-weighted document vector."""
        counts = Counter(tokenize(text))
        length = max(1, sum(counts.values()))
        length_ratio = length / self._average_length
        denominator_base = self.K1 * (1 - self.B + self.B * length_ratio)

        vector = [0.0] * len(self._vocabulary)
        for token, count in counts.items():
            index = self._vocabulary.get(token)
            if index is None:
                # Out-of-vocabulary terms are skipped rather than hashed into a
                # bucket, which is what caused spurious matches previously.
                continue
            saturation = (count * (self.K1 + 1)) / (count + denominator_base)
            vector[index] = saturation * self._idf[index]
        return _l2_normalise(vector)

    def _weigh_query(self, text: str) -> list[float]:
        """Query vector.

        Queries are short and have no meaningful length statistics, so they use
        IDF weighting with a mild repeated-term boost and no saturation. Both
        sides are L2-normalised, so only relative within-vector weighting
        matters.
        """
        counts = Counter(tokenize(text))
        vector = [0.0] * len(self._vocabulary)
        for token, count in counts.items():
            index = self._vocabulary.get(token)
            if index is None:
                continue
            vector[index] = (1.0 + math.log(count)) * self._idf[index]
        return _l2_normalise(vector)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self._require_fitted()
        return [self._weigh_document(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        self._require_fitted()
        return self._weigh_query(text)

    def _require_fitted(self) -> None:
        if not self._fitted:
            raise ConfigurationError(
                "The embedding provider must be fitted on the knowledge base before use."
            )

    def state(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "vocabulary": self._vocabulary,
            "idf": self._idf,
            "average_length": self._average_length,
        }

    def load_state(self, state: dict[str, Any]) -> bool:
        try:
            if state.get("name") != self.name:
                return False
            vocabulary = {str(key): int(value) for key, value in state["vocabulary"].items()}
            idf = [float(value) for value in state["idf"]]
            average_length = float(state["average_length"])
        except (KeyError, TypeError, ValueError):
            return False
        if len(vocabulary) != len(idf) or average_length <= 0:
            return False
        self._vocabulary = vocabulary
        self._idf = idf
        self._average_length = average_length
        self._fitted = True
        return True


class OpenAICompatibleEmbeddingProvider:
    """Semantic embeddings from an OpenAI-compatible ``/embeddings`` endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        dimension: int,
        timeout_seconds: int = 45,
        max_retries: int = 2,
    ) -> None:
        if not api_key:
            raise ConfigurationError(
                "EMBEDDING_API_KEY (or LLM_API_KEY) is required when "
                "EMBEDDING_PROVIDER=openai_compatible"
            )
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._dimension = dimension
        self._timeout = timeout_seconds
        self._max_retries = max(0, max_retries)

    @property
    def name(self) -> str:
        return "openai_compatible"

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def is_fitted(self) -> bool:
        # A hosted model needs no fitting step.
        return True

    def fit(self, corpus: Sequence[str]) -> None:
        return None

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []

        import httpx

        payload = {"model": self._model, "input": list(texts)}
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = httpx.post(
                    f"{self._base_url}/embeddings",
                    json=payload,
                    headers=headers,
                    timeout=self._timeout,
                )
                response.raise_for_status()
                body = response.json()
                vectors = [item["embedding"] for item in body["data"]]
                if len(vectors) != len(texts):
                    raise UpstreamServiceError(
                        "Embedding provider returned an unexpected number of vectors."
                    )
                return [_l2_normalise([float(value) for value in vector]) for vector in vectors]
            except UpstreamServiceError:
                raise
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "embedding_request_failed attempt=%d error=%s",
                    attempt + 1,
                    type(exc).__name__,
                )

        # Never surface the provider's raw error: it can echo request content.
        raise UpstreamServiceError("The embedding provider is unavailable.") from last_error

    def embed_query(self, text: str) -> list[float]:
        return self.embed([text])[0]

    def state(self) -> dict[str, Any]:
        # No fitted state; the model name identifies the vectors.
        return {"name": self.name, "model": self._model, "dimension": self._dimension}

    def load_state(self, state: dict[str, Any]) -> bool:
        return state.get("name") == self.name and int(state.get("dimension", 0)) == self._dimension


def get_embedding_provider(settings: Settings | None = None) -> EmbeddingProvider:
    """Build the configured embedding provider."""
    settings = settings or get_settings()

    if settings.embedding_provider == "openai_compatible":
        api_key = settings.embedding_api_key or settings.llm_api_key
        base_url = settings.embedding_base_url or settings.llm_base_url
        return OpenAICompatibleEmbeddingProvider(
            api_key=api_key,
            base_url=base_url,
            model=settings.embedding_model,
            dimension=settings.embedding_dim,
            timeout_seconds=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_retries,
        )

    return TfIdfEmbeddingProvider(max_features=settings.embedding_max_features)


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    """Cosine similarity for already-normalised vectors (a plain dot product)."""
    if len(left) != len(right):
        raise ValueError("vectors must have the same dimension")
    return float(sum(a * b for a, b in zip(left, right, strict=True)))


def fit_if_needed(provider: EmbeddingProvider, corpus: Iterable[str]) -> None:
    """Fit a lexical provider; no-op for providers that need no fitting."""
    if not provider.is_fitted:
        provider.fit(list(corpus))
