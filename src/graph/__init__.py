"""Knowledge graph.

Knowledge graph construction and traversal over Neo4j.

The layer turns the resolved knowledge corpus into a deterministic graph of
entities and explicit relationships. Every node traces to the record it came
from and every edge to the field that stated it, because a security graph is
only useful if each claim can be traced back to the line of data that made it.

It builds only what the corpus states. References go through the Stage-11
resolver; a reference that does not resolve produces no edge, an ambiguous one
produces no edge, and neither is replaced by a plausible substitute. Where a
relationship type has no supporting data in this snapshot, it is reported as
zero rather than filled in.

Neo4j is confined to :mod:`~src.graph.neo4j_store`, and its driver is imported
only when that store is constructed, so the whole layer builds and verifies
against :class:`InMemoryGraphStore` with no server running.

Typical use::

    builder = GraphBuilder.over(repository)
    graph = builder.build()
    GraphValidator().validate(graph).raise_if_invalid()
    InMemoryGraphStore().merge_nodes(graph.nodes)
"""

from __future__ import annotations

from .config import Neo4jSettings
from .exceptions import (
    GraphBackendUnavailableError,
    GraphBuildError,
    GraphError,
    GraphStoreError,
    GraphValidationError,
)
from .graph_builder import BUILD_ORDER, BuildSummary, GraphBuilder
from .graph_store import InMemoryGraphStore
from .graph_validator import GraphIssue, GraphValidationResult, GraphValidator
from .interfaces import GraphStore
from .models import (
    BuildDiagnostics,
    GraphNode,
    GraphRelationship,
    KnowledgeGraph,
    SkippedEdge,
    node_id,
    relationship_key,
)
from .node_builder import NodeBuilder
from .provenance import NodeProvenance, RelationshipProvenance
from .relationship_builder import EdgeBatch, RelationshipBuilder
from .types import EdgeOrigin, NodeType, RelationshipType, RuleCategory, SkipReason

__all__ = [
    "BUILD_ORDER",
    "BuildDiagnostics",
    "BuildSummary",
    "EdgeBatch",
    "EdgeOrigin",
    "GraphBackendUnavailableError",
    "GraphBuildError",
    "GraphBuilder",
    "GraphError",
    "GraphIssue",
    "GraphNode",
    "GraphRelationship",
    "GraphStore",
    "GraphStoreError",
    "GraphValidationError",
    "GraphValidationResult",
    "GraphValidator",
    "InMemoryGraphStore",
    "KnowledgeGraph",
    "Neo4jSettings",
    "NodeBuilder",
    "NodeProvenance",
    "NodeType",
    "RelationshipBuilder",
    "RelationshipProvenance",
    "RelationshipType",
    "RuleCategory",
    "SkipReason",
    "SkippedEdge",
    "node_id",
    "relationship_key",
]
