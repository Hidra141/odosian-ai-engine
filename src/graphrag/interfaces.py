"""GraphRAG contracts.

The roles retrieval is assembled from, as protocols.

A text retriever is defined by what it returns, not by how it decides. The MVP
answers lexically; an embedding retriever would satisfy the same protocol and
drop in without changing the hybrid pass, the ranker or the caller.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from .models import Candidate, Chunk, RetrievalQuery, RetrievalResult, RetrievalScore
from .provenance import SeedReport


@runtime_checkable
class ChunkSource(Protocol):
    """Provides the chunks retrieval works over."""

    def chunk(self, chunk_id: str) -> Chunk | None:
        """Return one chunk by id."""
        ...

    def chunks_of_record(self, parent_record_id: str) -> tuple[Chunk, ...]:
        """Return every chunk of one record, in document order."""
        ...


@runtime_checkable
class TextRetriever(Protocol):
    """Finds candidates by their text."""

    def retrieve(self, query: RetrievalQuery, limit: int) -> tuple[Candidate, ...]:
        """Return text candidates, best first, with their evidence attached."""
        ...


@runtime_checkable
class GraphRetriever(Protocol):
    """Finds candidates by walking the knowledge graph."""

    def retrieve(
        self,
        query: RetrievalQuery,
        limit: int,
    ) -> tuple[tuple[Candidate, ...], tuple[SeedReport, ...]]:
        """Return graph candidates and what the query's entities resolved to.

        The seed report is part of the contract: a caller must be able to see
        that an identifier resolved to nothing, or to several nodes, rather than
        inferring it from an absence of results.
        """
        ...


@runtime_checkable
class Ranker(Protocol):
    """Scores a candidate against a query."""

    def score(self, candidate: Candidate, query: RetrievalQuery) -> RetrievalScore:
        """Return the score of one candidate, with its components."""
        ...

    def rank(self, candidates: Sequence[Candidate], query: RetrievalQuery) -> tuple:
        """Return the candidates in rank order, with their scores."""
        ...


@runtime_checkable
class Retriever(Protocol):
    """Answers a query end to end."""

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        """Return the ranked, provenance-preserving result for a query."""
        ...
