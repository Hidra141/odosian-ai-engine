"""In-memory graph store.

Holds a graph in the process, under the same merge semantics a database would
apply.

It exists so the whole graph layer can be built and verified without a server
running. Merging by stable id means a second build overwrites rather than
appends, which is exactly what makes rebuilding idempotent — the property this
store lets us prove without Neo4j.

Insertion order is preserved so iteration is deterministic.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import final

from .models import GraphNode, GraphRelationship


@final
class InMemoryGraphStore:
    """Keeps nodes and edges in a dictionary, merging on their stable keys."""

    __slots__ = ("_nodes", "_relationships")

    def __init__(self) -> None:
        """Build an empty store."""
        self._nodes: dict[str, GraphNode] = {}
        self._relationships: dict[str, GraphRelationship] = {}

    @property
    def name(self) -> str:
        """Return the store's identifier."""
        return "in-memory"

    def merge_nodes(self, nodes: Iterable[GraphNode]) -> int:
        """Merge nodes by stable id and return how many were written."""
        written = 0
        for node in nodes:
            self._nodes[node.id] = node
            written += 1
        return written

    def merge_relationships(self, relationships: Iterable[GraphRelationship]) -> int:
        """Merge edges by stable key and return how many were written."""
        written = 0
        for relationship in relationships:
            self._relationships[relationship.key] = relationship
            written += 1
        return written

    def node_count(self) -> int:
        """Return how many distinct nodes the store holds."""
        return len(self._nodes)

    def relationship_count(self) -> int:
        """Return how many distinct edges the store holds."""
        return len(self._relationships)

    def get_node(self, node_id: str) -> GraphNode | None:
        """Return a node by stable id, or ``None``."""
        return self._nodes.get(node_id)

    def nodes(self) -> tuple[GraphNode, ...]:
        """Return every node, in the order it was first merged."""
        return tuple(self._nodes.values())

    def relationships(self) -> tuple[GraphRelationship, ...]:
        """Return every edge, in the order it was first merged."""
        return tuple(self._relationships.values())

    def clear(self) -> None:
        """Discard everything the store holds."""
        self._nodes.clear()
        self._relationships.clear()

    def close(self) -> None:
        """Release resources. The in-memory store holds none."""
        return None
