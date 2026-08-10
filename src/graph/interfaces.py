"""Graph store contract.

The interface every backend satisfies, expressed as a protocol so the domain
logic never mentions a database.

Both operations are merges: applying the same nodes and edges twice leaves the
store in the same state it reached the first time. That is what makes a rebuild
safe, and it is the only behaviour the builder depends on.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from .models import GraphNode, GraphRelationship


@runtime_checkable
class GraphStore(Protocol):
    """Persists nodes and edges under merge semantics."""

    @property
    def name(self) -> str:
        """Return the store's identifier, used in error messages."""
        ...

    def merge_nodes(self, nodes: Iterable[GraphNode]) -> int:
        """Merge nodes by stable id and return how many were written."""
        ...

    def merge_relationships(self, relationships: Iterable[GraphRelationship]) -> int:
        """Merge edges by stable key and return how many were written."""
        ...

    def node_count(self) -> int:
        """Return how many distinct nodes the store holds."""
        ...

    def relationship_count(self) -> int:
        """Return how many distinct edges the store holds."""
        ...

    def get_node(self, node_id: str) -> GraphNode | None:
        """Return a node by stable id, or ``None``."""
        ...

    def close(self) -> None:
        """Release any resources the store holds."""
        ...
