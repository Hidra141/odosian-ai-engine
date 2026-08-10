"""Graph building.

Walks the knowledge repository once and assembles the graph.

Nodes are built first, for every record, so that when references are resolved
their targets already exist. That ordering is why an edge can never point at a
node the build has not created: if a resolved record produced no node, the
candidate edge is recorded as skipped instead.

The build is deterministic. Sources are visited in a fixed order, records in
file order, and every identity is derived from content rather than from
iteration, so two runs over the same corpus produce the same nodes, the same
edge keys and the same properties.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, final

from src.knowledge.models.types import KnowledgeSource
from src.knowledge.normalizer.record_normalizer import DefaultKnowledgeNormalizer
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository
from src.knowledge.resolver.reference_resolver import DefaultKnowledgeResolver

from .interfaces import GraphStore
from .models import BuildDiagnostics, GraphNode, GraphRelationship, KnowledgeGraph, SkippedEdge
from .node_builder import NodeBuilder
from .relationship_builder import RelationshipBuilder

BUILD_ORDER: Final[tuple[KnowledgeSource, ...]] = (
    KnowledgeSource.MITRE,
    KnowledgeSource.ECS,
    KnowledgeSource.SIGMA,
    KnowledgeSource.ELASTIC,
    KnowledgeSource.LOLBAS,
)


@dataclass(frozen=True, slots=True)
class BuildSummary:
    """What one build produced."""

    graph: KnowledgeGraph
    records_read: int = 0
    nodes_written: int = 0
    relationships_written: int = 0


@final
@dataclass(frozen=True, slots=True)
class GraphBuilder:
    """Builds the knowledge graph from the Stage-11 repository."""

    repository: JsonlKnowledgeRepository
    resolver: DefaultKnowledgeResolver
    normalizer: DefaultKnowledgeNormalizer = field(default_factory=DefaultKnowledgeNormalizer)
    nodes: NodeBuilder = field(default_factory=NodeBuilder)

    @classmethod
    def over(cls, repository: JsonlKnowledgeRepository) -> GraphBuilder:
        """Build over a repository, wiring the Stage-11 resolver to it."""
        normalizer = DefaultKnowledgeNormalizer()
        return cls(
            repository=repository,
            resolver=DefaultKnowledgeResolver(repository, normalizer),
            normalizer=normalizer,
        )

    def build(self, sources: Sequence[KnowledgeSource] | None = None) -> KnowledgeGraph:
        """Assemble the graph from the corpus, in a fixed source order."""
        selected = self._sources(sources)
        normalized_records = []
        node_list: list[GraphNode] = []
        nodes_by_record: dict[str, GraphNode] = {}

        for source in selected:
            for record in self.repository.iterate_source(source):
                normalized = self.normalizer.normalize(record)
                normalized_records.append(normalized)
                node = self.nodes.build(normalized)
                if node is None:
                    continue
                nodes_by_record[record.id] = node
                node_list.append(node)

        relationships = RelationshipBuilder(self.resolver, self.nodes)
        edges: list[GraphRelationship] = []
        extra_nodes: list[GraphNode] = []
        skipped: list[SkippedEdge] = []

        for normalized in normalized_records:
            start = nodes_by_record.get(normalized.record.id)
            if start is None:
                continue
            batch = relationships.build(normalized, start, nodes_by_record)
            edges.extend(batch.relationships)
            extra_nodes.extend(batch.extra_nodes)
            skipped.extend(batch.skipped)

        all_nodes = self._merge_nodes(node_list, extra_nodes)
        return KnowledgeGraph(
            nodes=all_nodes,
            relationships=self._merge_edges(edges),
            diagnostics=BuildDiagnostics(tuple(skipped)),
        )

    def build_into(
        self,
        store: GraphStore,
        sources: Sequence[KnowledgeSource] | None = None,
    ) -> BuildSummary:
        """Build the graph and merge it into a store."""
        graph = self.build(sources)
        return BuildSummary(
            graph=graph,
            records_read=sum(self.repository.count(item) for item in self._sources(sources)),
            nodes_written=store.merge_nodes(graph.nodes),
            relationships_written=store.merge_relationships(graph.relationships),
        )

    def _sources(self, sources: Sequence[KnowledgeSource] | None) -> tuple[KnowledgeSource, ...]:
        """Return the sources to visit, in the fixed build order."""
        available = self.repository.available_sources()
        wanted = set(sources) if sources is not None else set(available)
        return tuple(item for item in BUILD_ORDER if item in available and item in wanted)

    def _merge_nodes(
        self,
        primary: Sequence[GraphNode],
        derived: Sequence[GraphNode],
    ) -> tuple[GraphNode, ...]:
        """Return the nodes deduplicated by stable id, first occurrence winning."""
        merged: dict[str, GraphNode] = {}
        for node in (*primary, *derived):
            merged.setdefault(node.id, node)
        return tuple(merged.values())

    def _merge_edges(self, edges: Sequence[GraphRelationship]) -> tuple[GraphRelationship, ...]:
        """Return the edges deduplicated by stable key, first occurrence winning.

        Distinct evidence produces distinct keys, so two rules citing the same
        technique survive as two edges. Only an identical restatement collapses.
        """
        merged: dict[str, GraphRelationship] = {}
        for edge in edges:
            merged.setdefault(edge.key, edge)
        return tuple(merged.values())
