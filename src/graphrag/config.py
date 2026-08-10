"""GraphRAG configuration.

Every number this layer uses, in one place, none of them hardcoded at a call
site.

Stage-05's configuration system is frozen and has no retrieval section, so the
settings live here and can be built from a mapping using the frozen coercion
helpers. The defaults are documented values, not magic constants: each one is
stated with the reason it has the value it does.

No credential is introduced. Retrieval reads local files and talks to nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from src.config.coercion import as_float, as_int, as_optional_path, get_section
from src.config.types import ConfigMapping
from src.knowledge.models.types import KnowledgeSource

from .types import SectionType


def _default_source_weights() -> Mapping[KnowledgeSource, float]:
    """Return the default source authority weights.

    MITRE and Sigma answer the questions this engine asks most directly, so they
    carry full weight. ECS is documentation for field names: valuable when a
    field is asked about by name, but it must not outrank a matching detection
    rule merely because its prose shares words, so its base weight is low and it
    is raised only when the query names a field.
    """
    return MappingProxyType(
        {
            KnowledgeSource.MITRE: 1.00,
            KnowledgeSource.SIGMA: 1.00,
            KnowledgeSource.ELASTIC: 0.95,
            KnowledgeSource.LOLBAS: 0.85,
            KnowledgeSource.ECS: 0.55,
        }
    )


def _default_section_weights() -> Mapping[SectionType, float]:
    """Return the default section weights.

    Detection logic and descriptions carry the knowledge a caller is usually
    after; reference lists and tag lists are navigational and rank below them.
    """
    return MappingProxyType(
        {
            SectionType.DETECTION: 1.00,
            SectionType.QUERY: 1.00,
            SectionType.DESCRIPTION: 0.95,
            SectionType.COMMAND: 0.90,
            SectionType.CONDITION: 0.85,
            SectionType.SUMMARY: 0.85,
            SectionType.FIELD: 0.85,
            SectionType.USAGE: 0.75,
            SectionType.FALSE_POSITIVES: 0.70,
            SectionType.PLATFORMS: 0.65,
            SectionType.RELATIONSHIPS: 0.65,
            SectionType.METADATA: 0.60,
            SectionType.TAGS: 0.45,
            SectionType.REFERENCES: 0.35,
            SectionType.OTHER: 0.60,
        }
    )


@dataclass(frozen=True, slots=True)
class RankingWeights:
    """How much each scoring component contributes.

    The weights sum to 1.0 so a total is a proportion of a perfect match.
    Identifier and entity agreement dominate because an exact ATT&CK identifier
    is a fact, while lexical overlap is only a hint.
    """

    exact_identifier: float = 0.30
    entity_match: float = 0.20
    graph: float = 0.20
    lexical: float = 0.15
    source: float = 0.07
    distance: float = 0.05
    section: float = 0.03

    @property
    def total(self) -> float:
        """Return the sum of the weights, which should be 1.0."""
        return (
            self.exact_identifier
            + self.entity_match
            + self.graph
            + self.lexical
            + self.source
            + self.distance
            + self.section
        )

    @classmethod
    def from_mapping(cls, data: ConfigMapping) -> RankingWeights:
        """Build weights from a configuration section."""
        return cls(
            exact_identifier=as_float(data, "exact_identifier", default=0.30),
            entity_match=as_float(data, "entity_match", default=0.20),
            graph=as_float(data, "graph", default=0.20),
            lexical=as_float(data, "lexical", default=0.15),
            source=as_float(data, "source", default=0.07),
            distance=as_float(data, "distance", default=0.05),
            section=as_float(data, "section", default=0.03),
        )


@dataclass(frozen=True, slots=True)
class GraphRagSettings:
    """Chunking, indexing, traversal and ranking settings."""

    max_chunk_chars: int = 2000
    """Bound on a chunk. Above this a section is split into ordered parts."""

    min_chunk_chars: int = 40
    """Below this a fragment is merged into its neighbour instead of standing alone."""

    chunk_overlap_chars: int = 100
    """Overlap between the parts of a split section, so a match at a boundary survives."""

    top_k: int = 10
    """How many items a query returns unless it asks for another number."""

    candidate_limit: int = 200
    """How many candidates each route contributes before merging."""

    max_hops: int = 2
    """Traversal bound. Every walk stops here; there is no unbounded traversal."""

    bm25_k1: float = 1.2
    bm25_b: float = 0.75
    ecs_field_query_weight: float = 1.00
    """Weight ECS takes when the query names a field, instead of its low base."""

    index_dir: Path | None = None
    """Where a derived index may be persisted. Never inside the raw corpus."""

    weights: RankingWeights = field(default_factory=RankingWeights)
    source_weights: Mapping[KnowledgeSource, float] = field(
        default_factory=_default_source_weights
    )
    section_weights: Mapping[SectionType, float] = field(
        default_factory=_default_section_weights
    )

    @classmethod
    def from_mapping(cls, data: ConfigMapping) -> GraphRagSettings:
        """Build settings from a ``graphrag`` configuration section."""
        section = get_section(data, "graphrag")
        weights_section = section.get("weights")
        weights = (
            RankingWeights.from_mapping(weights_section)
            if isinstance(weights_section, Mapping)
            else RankingWeights()
        )
        return cls(
            max_chunk_chars=as_int(section, "max_chunk_chars", default=2000),
            min_chunk_chars=as_int(section, "min_chunk_chars", default=40),
            chunk_overlap_chars=as_int(section, "chunk_overlap_chars", default=100),
            top_k=as_int(section, "top_k", default=10),
            candidate_limit=as_int(section, "candidate_limit", default=200),
            max_hops=as_int(section, "max_hops", default=2),
            bm25_k1=as_float(section, "bm25_k1", default=1.2),
            bm25_b=as_float(section, "bm25_b", default=0.75),
            ecs_field_query_weight=as_float(section, "ecs_field_query_weight", default=1.0),
            index_dir=as_optional_path(section, "index_dir"),
            weights=weights,
        )

    def source_weight(self, source: KnowledgeSource, *, query_names_field: bool) -> float:
        """Return a source's authority weight for one query.

        ECS is raised only when the query actually names a field, which is the
        one case where field documentation is the answer rather than noise.
        """
        if source is KnowledgeSource.ECS and query_names_field:
            return self.ecs_field_query_weight
        return self.source_weights.get(source, 0.5)

    def section_weight(self, section: SectionType) -> float:
        """Return a section's weight."""
        return self.section_weights.get(section, 0.6)
