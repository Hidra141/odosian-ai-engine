"""Knowledge graph models.

Nodes, edges, the graph they form, and the diagnostics from building it.

Identity is deterministic and content-free of ordering: a node is
``<source>:<type>:<canonical id>`` and an edge is its endpoints, its type and
its evidence. Building the same corpus twice therefore produces the same
identities, which is what makes a merge into a store idempotent.

Diagnostics are part of the result, not a log. A reference that did not become
an edge is recorded with the reason, so the graph can be read together with an
account of what it deliberately omits.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from src.knowledge.models.types import KnowledgeSource

from .provenance import NodeProvenance, RelationshipProvenance
from .types import NodeType, RelationshipType, SkipReason

DERIVED_PREFIX = "derived"


def _empty_properties() -> Mapping[str, str]:
    """Return an immutable, empty property mapping."""
    return MappingProxyType({})


def node_id(source: KnowledgeSource | None, node_type: NodeType, canonical_id: str) -> str:
    """Return the stable identity of a node.

    The scheme is uniform across every node type so a store can merge on one
    key. Nodes with no dataset behind them — tags, external identifiers — use a
    ``derived`` prefix rather than borrowing a source they did not come from.
    """
    prefix = source.value if source is not None else DERIVED_PREFIX
    return f"{prefix}:{node_type.value}:{canonical_id}"


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One entity in the graph."""

    id: str
    node_type: NodeType
    source: KnowledgeSource | None
    source_id: str
    canonical_id: str
    name: str | None = None
    properties: Mapping[str, str] = field(default_factory=_empty_properties)
    provenance: NodeProvenance | None = None

    @property
    def identity(self) -> tuple[str, str, str]:
        """Return the tuple a store should merge on."""
        return (
            self.source.value if self.source is not None else DERIVED_PREFIX,
            self.node_type.value,
            self.canonical_id,
        )

    def __str__(self) -> str:
        """Return the node rendered for a report line."""
        return f"({self.node_type.value} {self.id})"


@dataclass(frozen=True, slots=True)
class GraphRelationship:
    """One edge in the graph, with the evidence that produced it."""

    key: str
    relationship_type: RelationshipType
    start_id: str
    end_id: str
    provenance: RelationshipProvenance
    properties: Mapping[str, str] = field(default_factory=_empty_properties)

    def __str__(self) -> str:
        """Return the edge rendered for a report line."""
        return f"{self.start_id} -[{self.relationship_type.value}]-> {self.end_id}"


def relationship_key(
    start_id: str,
    relationship_type: RelationshipType,
    end_id: str,
    provenance: RelationshipProvenance,
) -> str:
    """Return the stable identity of an edge, including its evidence."""
    return f"{start_id}|{relationship_type.value}|{end_id}|{provenance.evidence_key}"


@dataclass(frozen=True, slots=True)
class SkippedEdge:
    """A candidate edge that was deliberately not created."""

    reason: SkipReason
    source: KnowledgeSource
    source_id: str
    source_field: str
    original_value: str
    candidates: tuple[str, ...] = ()
    note: str = ""

    def __str__(self) -> str:
        """Return the skip rendered for a report line."""
        return (
            f"{self.source.value}:{self.source_id} {self.source_field}="
            f"{self.original_value!r} -> {self.reason.value}"
        )


@dataclass(frozen=True, slots=True)
class BuildDiagnostics:
    """What the build chose not to do, and why."""

    skipped: tuple[SkippedEdge, ...] = ()

    def of_reason(self, reason: SkipReason) -> tuple[SkippedEdge, ...]:
        """Return the skipped edges with one reason, in build order."""
        return tuple(item for item in self.skipped if item.reason is reason)

    @property
    def counts(self) -> Mapping[SkipReason, int]:
        """Return how many candidate edges each reason accounts for."""
        tally: dict[SkipReason, int] = {reason: 0 for reason in SkipReason}
        for item in self.skipped:
            tally[item.reason] += 1
        return MappingProxyType(tally)


@dataclass(frozen=True, slots=True)
class KnowledgeGraph:
    """A built graph: its nodes, its edges and the account of what it omits."""

    nodes: tuple[GraphNode, ...] = ()
    relationships: tuple[GraphRelationship, ...] = ()
    diagnostics: BuildDiagnostics = field(default_factory=BuildDiagnostics)

    def __len__(self) -> int:
        """Return how many nodes the graph holds."""
        return len(self.nodes)

    def __iter__(self) -> Iterator[GraphNode]:
        """Iterate the nodes in build order."""
        return iter(self.nodes)

    def node(self, identifier: str) -> GraphNode | None:
        """Return a node by its stable id, or ``None``."""
        for item in self.nodes:
            if item.id == identifier:
                return item
        return None

    def nodes_of(self, node_type: NodeType) -> tuple[GraphNode, ...]:
        """Return every node of one type, in build order."""
        return tuple(item for item in self.nodes if item.node_type is node_type)

    def relationships_of(self, relationship_type: RelationshipType) -> tuple[GraphRelationship, ...]:
        """Return every edge of one type, in build order."""
        return tuple(
            item for item in self.relationships if item.relationship_type is relationship_type
        )

    def node_counts(self) -> Mapping[NodeType, int]:
        """Return how many nodes exist of each type, including zeros."""
        tally: dict[NodeType, int] = {item: 0 for item in NodeType}
        for node in self.nodes:
            tally[node.node_type] += 1
        return MappingProxyType(tally)

    def relationship_counts(self) -> Mapping[RelationshipType, int]:
        """Return how many edges exist of each type, including zeros.

        Types with no edges are reported rather than omitted, so a relationship
        the corpus cannot support is visible instead of missing.
        """
        tally: dict[RelationshipType, int] = {item: 0 for item in RelationshipType}
        for relationship in self.relationships:
            tally[relationship.relationship_type] += 1
        return MappingProxyType(tally)

    def with_parts(
        self,
        nodes: Sequence[GraphNode],
        relationships: Sequence[GraphRelationship],
    ) -> KnowledgeGraph:
        """Return a copy carrying different nodes and edges."""
        return KnowledgeGraph(
            nodes=tuple(nodes),
            relationships=tuple(relationships),
            diagnostics=self.diagnostics,
        )
