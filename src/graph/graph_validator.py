"""Graph validation.

Checks that a built graph is internally consistent before it is written
anywhere.

The checks are about structure, not about how complete the graph looks. A graph
with few edges is not invalid; a graph with an edge pointing at a node that does
not exist is. Every issue is collected before reporting, so one run names every
problem.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import final

from .exceptions import GraphValidationError
from .models import KnowledgeGraph
from .types import NodeType, SkipReason


@dataclass(frozen=True, slots=True)
class GraphIssue:
    """One problem found in a built graph."""

    check: str
    detail: str

    def __str__(self) -> str:
        """Return the issue rendered as ``check: detail``."""
        return f"{self.check}: {self.detail}"


@dataclass(frozen=True, slots=True)
class GraphValidationResult:
    """The outcome of validating a graph."""

    issues: tuple[GraphIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        """Return whether the graph passed every check."""
        return not self.issues

    def raise_if_invalid(self) -> None:
        """Raise :class:`GraphValidationError` when any issue was found."""
        if self.issues:
            raise GraphValidationError([str(item) for item in self.issues])


@final
class GraphValidator:
    """Checks a built graph for internal consistency."""

    __slots__ = ()

    def validate(self, graph: KnowledgeGraph) -> GraphValidationResult:
        """Run every check and collect the issues."""
        return GraphValidationResult(
            (
                *self._duplicate_nodes(graph),
                *self._dangling_edges(graph),
                *self._missing_provenance(graph),
                *self._ambiguous_targets(graph),
                *self._fabricated_targets(graph),
            )
        )

    def _duplicate_nodes(self, graph: KnowledgeGraph) -> Iterator[GraphIssue]:
        """Yield an issue for any stable node identity used twice."""
        seen: dict[str, int] = {}
        for node in graph.nodes:
            seen[node.id] = seen.get(node.id, 0) + 1
        for identifier, count in seen.items():
            if count > 1:
                yield GraphIssue("duplicate_node_id", f"{identifier} appears {count} times")

    def _dangling_edges(self, graph: KnowledgeGraph) -> Iterator[GraphIssue]:
        """Yield an issue for any edge whose endpoints are not both present."""
        known = {node.id for node in graph.nodes}
        for relationship in graph.relationships:
            if relationship.start_id not in known:
                yield GraphIssue("dangling_start", f"{relationship.key} starts at an absent node")
            if relationship.end_id not in known:
                yield GraphIssue("dangling_end", f"{relationship.key} ends at an absent node")

    def _missing_provenance(self, graph: KnowledgeGraph) -> Iterator[GraphIssue]:
        """Yield an issue for any edge without evidence, or dataset node without provenance."""
        for relationship in graph.relationships:
            if not relationship.provenance.source_field:
                yield GraphIssue("missing_edge_provenance", f"{relationship.key} names no field")
        for node in graph.nodes:
            if node.source is not None and node.provenance is None:
                yield GraphIssue("missing_node_provenance", f"{node.id} carries no provenance")

    def _ambiguous_targets(self, graph: KnowledgeGraph) -> Iterator[GraphIssue]:
        """Yield an issue if any edge was built from an ambiguous resolution."""
        ambiguous = {
            item.original_value for item in graph.diagnostics.of_reason(SkipReason.AMBIGUOUS_TARGET)
        }
        for relationship in graph.relationships:
            provenance = relationship.provenance
            if provenance.resolution_status == "ambiguous":
                yield GraphIssue(
                    "ambiguous_target_selected",
                    f"{relationship.key} was built from an ambiguous resolution",
                )
            if provenance.original_value in ambiguous and provenance.canonical_id:
                yield GraphIssue(
                    "ambiguous_target_selected",
                    f"{relationship.key} targets a value recorded as ambiguous",
                )

    def _fabricated_targets(self, graph: KnowledgeGraph) -> Iterator[GraphIssue]:
        """Yield an issue for any node standing in for a record that was never loaded.

        Tag and external reference nodes are exempt: they carry no source and
        make no claim that a dataset describes them.
        """
        for node in graph.nodes:
            if node.node_type in (NodeType.TAG, NodeType.EXTERNAL_REFERENCE):
                if node.source is not None:
                    yield GraphIssue(
                        "derived_node_claims_source",
                        f"{node.id} claims to come from a dataset",
                    )
                continue
            if node.source is None:
                yield GraphIssue("node_without_source", f"{node.id} has no dataset behind it")
