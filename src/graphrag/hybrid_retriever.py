"""Hybrid retrieval.

Combines the two routes into one ranked set.

The merge is by chunk, and it *accumulates* evidence rather than replacing it: a
chunk found lexically and by traversal ends up carrying both pieces of evidence,
which is what lets the ranker treat agreement between routes as stronger than
either alone. Nothing probabilistic is introduced to express that — the two
components simply both contribute.

Deduplication is careful about what a duplicate is. Two chunks of one record are
different items. Two rules pointing at one technique are different items. Only
the same chunk arriving twice is one item, and even then its evidence entries
are kept separate.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import final

from .config import GraphRagSettings
from .filters import CandidateFilter
from .graph_retriever import KnowledgeGraphRetriever
from .models import (
    Candidate,
    RetrievalItem,
    RetrievalQuery,
    RetrievalResult,
    RetrievalStatistics,
)
from .provenance import RetrievalProvenance, SeedReport, merge_methods
from .ranking import DeterministicRanker
from .text_retriever import LexicalTextRetriever
from .types import RetrievalMode


@final
@dataclass(frozen=True, slots=True)
class HybridRetriever:
    """Runs the routes a mode asks for, merges them and ranks the result."""

    text: LexicalTextRetriever
    graph: KnowledgeGraphRetriever
    ranker: DeterministicRanker
    settings: GraphRagSettings
    filters: CandidateFilter = CandidateFilter()

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        """Return the ranked, provenance-preserving result for a query."""
        limit = max(self.settings.candidate_limit, query.max_results)
        text_candidates: tuple[Candidate, ...] = ()
        graph_candidates: tuple[Candidate, ...] = ()
        seeds: tuple[SeedReport, ...] = ()

        if query.mode in (RetrievalMode.TEXT, RetrievalMode.HYBRID):
            text_candidates = self.text.retrieve(query, limit)
        if query.mode in (RetrievalMode.GRAPH, RetrievalMode.HYBRID):
            graph_candidates, seeds = self.graph.retrieve(query, limit)

        merged = self._merge(text_candidates, graph_candidates)
        outcome = self.filters.apply(merged, query)
        ranked = self.ranker.rank(outcome.kept, query)
        top = ranked[: query.max_results or self.settings.top_k]

        items = tuple(
            RetrievalItem(
                chunk=candidate.chunk,
                score=score,
                provenance=self._provenance(candidate),
            )
            for candidate, score in top
        )
        statistics = RetrievalStatistics(
            text_candidates=len(text_candidates),
            graph_candidates=len(graph_candidates),
            merged_candidates=len(merged),
            filtered_out=outcome.removed,
            returned=len(items),
            graph_nodes_visited=self.graph.node_count if graph_candidates else 0,
            max_hops_used=self._max_hops(graph_candidates),
        )
        return RetrievalResult(
            query=query,
            mode=query.mode,
            items=items,
            total_candidates=len(merged),
            statistics=statistics,
            seeds=seeds,
        )

    def _merge(
        self,
        text_candidates: Sequence[Candidate],
        graph_candidates: Sequence[Candidate],
    ) -> tuple[Candidate, ...]:
        """Merge candidates by chunk, accumulating evidence from every route."""
        merged: dict[str, Candidate] = {}
        for candidate in (*text_candidates, *graph_candidates):
            key = candidate.chunk.chunk_id
            existing = merged.get(key)
            merged[key] = (
                candidate if existing is None else existing.with_evidence(candidate.evidence)
            )
        return tuple(merged.values())

    def _provenance(self, candidate: Candidate) -> RetrievalProvenance:
        """Assemble the account of why one candidate is in the result."""
        chunk = candidate.chunk
        return RetrievalProvenance(
            source=chunk.source,
            source_id=chunk.source_id,
            parent_record_id=chunk.parent_record_id,
            chunk_id=chunk.chunk_id,
            section=chunk.section,
            location=chunk.provenance.location if chunk.provenance else "",
            methods=merge_methods(candidate.evidence),
            evidence=candidate.evidence,
        )

    def _max_hops(self, candidates: Sequence[Candidate]) -> int:
        """Return the deepest hop count any graph evidence used."""
        return max(
            (evidence.hops for item in candidates for evidence in item.evidence),
            default=0,
        )
