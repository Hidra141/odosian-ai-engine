"""Ranking ablation.

Re-ranks the same candidates under modified weights, to see which scoring
component actually earns its place.

**Production ranking is untouched.** Each variant is a fresh
:class:`GraphRagSettings` with one weight set to zero, wired into a
:class:`HybridRetriever` built from Stage-13's own public classes and sharing
the already-built text index. Nothing is reimplemented and no production object
is mutated.

Weights are not renormalised after a component is removed. Metrics depend on
the *order* of results, not the magnitude of scores, and renormalising would
silently redistribute the removed weight across the survivors — changing more
than the one thing the variant means to change.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import final

from src.graph.models import KnowledgeGraph
from src.graphrag.config import GraphRagSettings, RankingWeights
from src.graphrag.filters import CandidateFilter
from src.graphrag.graph_retriever import KnowledgeGraphRetriever
from src.graphrag.hybrid_retriever import HybridRetriever
from src.graphrag.ranking import DeterministicRanker
from src.graphrag.text_index import TextIndex
from src.graphrag.text_retriever import LexicalTextRetriever

from .types import AblationVariant


def variant_weights(base: RankingWeights, variant: AblationVariant) -> RankingWeights:
    """Return the weights for one variant, with a single component removed."""
    if variant is AblationVariant.FULL:
        return base
    if variant is AblationVariant.NO_GRAPH:
        return replace(base, graph=0.0)
    if variant is AblationVariant.NO_EXACT_IDENTIFIER:
        return replace(base, exact_identifier=0.0)
    if variant is AblationVariant.NO_ENTITY_MATCH:
        return replace(base, entity_match=0.0)
    return replace(base, source=0.0)


@final
@dataclass(frozen=True, slots=True)
class AblationHarness:
    """Builds retrievers that differ only in their ranking weights."""

    index: TextIndex
    graph: KnowledgeGraph
    base_settings: GraphRagSettings

    def retriever_for(self, variant: AblationVariant) -> HybridRetriever:
        """Return a retriever ranking under one variant's weights.

        The text index and the graph are shared, so a variant costs a re-rank
        rather than a rebuild.
        """
        settings = replace(
            self.base_settings,
            weights=variant_weights(self.base_settings.weights, variant),
        )
        return HybridRetriever(
            text=LexicalTextRetriever(index=self.index),
            graph=KnowledgeGraphRetriever(self.graph, self.index, settings),
            ranker=DeterministicRanker(settings=settings),
            settings=settings,
            filters=CandidateFilter(),
        )
