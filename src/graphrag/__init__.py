"""GraphRAG.

Graph-aware retrieval and ranking of contextual evidence.

The layer answers a question of the form "given this rule or query, what does
the corpus actually say?" by combining two routes: a walk of the Stage-12
knowledge graph, and a lexical search over chunks derived from the Stage-11
records. Candidates from both are merged, filtered, scored by a documented
deterministic formula, and returned with the evidence that produced them.

It retrieves. It does not reason, summarise or answer, and it never calls a
language model — no embedding service, no vector store, no network.

It does not make the corpus look more complete than it is. An identifier no node
carries is reported unresolved; one that several nodes carry is reported
ambiguous with every candidate listed and none chosen. Nothing is manufactured
to fill a gap.

The raw datasets are never written to. Chunks and indexes are derived structures
that live outside the corpus, and persistence refuses any path inside it.

Typical use::

    retriever = GraphRagRetriever(repository, graph, settings)
    retriever.build_index()
    result = retriever.retrieve(
        RetrievalQuery(text="encoded powershell", entity_ids=("T1059.001",))
    )
"""

from __future__ import annotations

from .attack_redirects import ATTACK_REDIRECTS, AttackRedirect, redirect_for
from .chunking import RecordChunker, Segment, iter_chunks
from .config import GraphRagSettings, RankingWeights
from .exceptions import (
    GraphRagError,
    IndexNotBuiltError,
    IndexPersistenceError,
    InvalidRetrievalQueryError,
    RetrievalValidationError,
)
from .filters import CandidateFilter, FilterOutcome, by_section, by_source
from .graph_retriever import GraphView, KnowledgeGraphRetriever
from .hybrid_retriever import HybridRetriever
from .interfaces import ChunkSource, GraphRetriever, Ranker, Retriever, TextRetriever
from .models import (
    Candidate,
    Chunk,
    RetrievalItem,
    RetrievalQuery,
    RetrievalResult,
    RetrievalScore,
    RetrievalStatistics,
)
from .provenance import (
    ChunkProvenance,
    GraphPathStep,
    RetrievalEvidence,
    RetrievalProvenance,
    SeedReport,
    redirect_groups,
)
from .ranking import DeterministicRanker
from .retriever import BuildReport, GraphRagRetriever
from .text_index import IndexStatistics, TextIndex, tokenize
from .text_retriever import LexicalTextRetriever
from .types import MatchKind, RetrievalMethod, RetrievalMode, SectionType, SeedStatus
from .validation import RetrievalIssue, RetrievalValidationResult, RetrievalValidator

__all__ = [
    "ATTACK_REDIRECTS",
    "AttackRedirect",
    "BuildReport",
    "Candidate",
    "CandidateFilter",
    "Chunk",
    "ChunkProvenance",
    "ChunkSource",
    "DeterministicRanker",
    "FilterOutcome",
    "GraphPathStep",
    "GraphRagError",
    "GraphRagRetriever",
    "GraphRagSettings",
    "GraphRetriever",
    "GraphView",
    "HybridRetriever",
    "IndexNotBuiltError",
    "IndexPersistenceError",
    "IndexStatistics",
    "InvalidRetrievalQueryError",
    "KnowledgeGraphRetriever",
    "LexicalTextRetriever",
    "MatchKind",
    "Ranker",
    "RankingWeights",
    "RecordChunker",
    "RetrievalEvidence",
    "RetrievalIssue",
    "RetrievalItem",
    "RetrievalMethod",
    "RetrievalMode",
    "RetrievalProvenance",
    "RetrievalQuery",
    "RetrievalResult",
    "RetrievalScore",
    "RetrievalStatistics",
    "RetrievalValidationError",
    "RetrievalValidationResult",
    "RetrievalValidator",
    "Retriever",
    "SectionType",
    "SeedReport",
    "SeedStatus",
    "Segment",
    "TextIndex",
    "TextRetriever",
    "by_section",
    "by_source",
    "iter_chunks",
    "redirect_for",
    "redirect_groups",
    "tokenize",
]
