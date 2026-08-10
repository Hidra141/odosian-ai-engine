"""GraphRAG entry point.

Builds the retrieval indexes once, then answers queries against them.

``build_index`` walks the corpus, chunks it and indexes the chunks; it also
takes the Stage-12 graph and computes an adjacency view. Both are held on the
instance, so a query costs a lookup rather than a rebuild. Nothing is cached at
module level and no singleton exists: two retrievers never share state.

The result is the end of Stage-13. It is ranked, it explains every item, and it
reports what the query's entities did not resolve to. Turning it into a prompt
is the next stage's work.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import final

from src.graph.models import KnowledgeGraph
from src.knowledge.models.types import KnowledgeSource
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository

from .chunking import RecordChunker
from .config import GraphRagSettings
from .exceptions import IndexNotBuiltError, InvalidRetrievalQueryError
from .filters import CandidateFilter
from .graph_retriever import KnowledgeGraphRetriever
from .hybrid_retriever import HybridRetriever
from .models import Chunk, RetrievalQuery, RetrievalResult
from .ranking import DeterministicRanker
from .text_index import IndexStatistics, TextIndex
from .text_retriever import LexicalTextRetriever


@dataclass(frozen=True, slots=True)
class BuildReport:
    """What building the indexes produced."""

    records: int = 0
    chunks: int = 0
    index: IndexStatistics = IndexStatistics()
    graph_nodes: int = 0
    chunks_per_source: tuple[tuple[str, int], ...] = ()


@final
class GraphRagRetriever:
    """Answers retrieval queries over the corpus and the knowledge graph."""

    __slots__ = ("_settings", "_repository", "_graph", "_index", "_hybrid", "_chunks", "_report")

    def __init__(
        self,
        repository: JsonlKnowledgeRepository,
        graph: KnowledgeGraph,
        settings: GraphRagSettings | None = None,
    ) -> None:
        """Hold the inputs. No corpus is read until :meth:`build_index`."""
        self._settings = settings if settings is not None else GraphRagSettings()
        self._repository = repository
        self._graph = graph
        self._index = TextIndex(self._settings)
        self._hybrid: HybridRetriever | None = None
        self._chunks: tuple[Chunk, ...] = ()
        self._report = BuildReport()

    @property
    def settings(self) -> GraphRagSettings:
        """Return the settings this retriever was built with."""
        return self._settings

    @property
    def is_built(self) -> bool:
        """Return whether the indexes are ready."""
        return self._hybrid is not None

    @property
    def chunks(self) -> tuple[Chunk, ...]:
        """Return every chunk the index holds, in build order."""
        return self._chunks

    @property
    def index(self) -> TextIndex:
        """Return the text index."""
        return self._index

    @property
    def report(self) -> BuildReport:
        """Return the report of the last build."""
        return self._report

    def build_index(self, sources: Sequence[KnowledgeSource] | None = None) -> BuildReport:
        """Chunk and index the corpus, and prepare the graph view."""
        chunker = RecordChunker(settings=self._settings)
        selected = tuple(sources) if sources else self._repository.available_sources()

        chunks: list[Chunk] = []
        records = 0
        for source in selected:
            for record in self._repository.iterate_source(source):
                records += 1
                chunks.extend(chunker.chunk(record))

        self._chunks = tuple(chunks)
        statistics = self._index.build(self._chunks)
        self._hybrid = HybridRetriever(
            text=LexicalTextRetriever(index=self._index),
            graph=KnowledgeGraphRetriever(self._graph, self._index, self._settings),
            ranker=DeterministicRanker(settings=self._settings),
            settings=self._settings,
            filters=CandidateFilter(),
        )
        self._report = BuildReport(
            records=records,
            chunks=len(self._chunks),
            index=statistics,
            graph_nodes=len(self._graph.nodes),
            chunks_per_source=tuple(sorted(statistics.per_source.items())),
        )
        return self._report

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        """Answer one query."""
        if self._hybrid is None:
            raise IndexNotBuiltError("GraphRagRetriever")
        if query.is_empty:
            raise InvalidRetrievalQueryError("query states neither text nor entities")
        if query.max_results <= 0:
            raise InvalidRetrievalQueryError("max_results must be positive")
        return self._hybrid.retrieve(query)
