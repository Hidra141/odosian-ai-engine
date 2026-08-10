"""Graph retrieval.

Answers a query by walking the Stage-12 knowledge graph.

The graph is used, never rebuilt and never re-derived. An adjacency view is
computed once from the graph object and reused for every query, so a lookup does
not scan 13,000 nodes.

Seeding is the only place identifiers meet the graph, and it is where the
corpus's honesty is preserved. An identifier that no node carries is reported
unresolved and contributes nothing — ``T1562`` finds no node and no node is
manufactured for it. An identifier several nodes carry is reported ambiguous
with every candidate listed and **no seed chosen**, so ``M1013`` never silently
becomes the enterprise one.

Every walk is bounded by the configured hop limit. There is no unbounded
traversal, and the frontier stops expanding once the limit is reached.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import final

from src.graph.models import GraphNode, GraphRelationship, KnowledgeGraph

from .config import GraphRagSettings
from .filters import query_predicate
from .interfaces import ChunkSource
from .models import Candidate, RetrievalQuery
from .provenance import GraphPathStep, RetrievalEvidence, SeedReport
from .types import MatchKind, RetrievalMethod, SeedStatus


@dataclass(frozen=True, slots=True)
class GraphView:
    """An adjacency view over a built graph, computed once."""

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    out_edges: dict[str, list[GraphRelationship]] = field(default_factory=dict)
    in_edges: dict[str, list[GraphRelationship]] = field(default_factory=dict)
    by_identifier: dict[str, list[str]] = field(default_factory=dict)
    by_record: dict[str, str] = field(default_factory=dict)

    @classmethod
    def of(cls, graph: KnowledgeGraph) -> GraphView:
        """Build the adjacency view of a graph."""
        view = cls()
        for node in graph.nodes:
            view.nodes[node.id] = node
            for key in _identifier_keys(node):
                view.by_identifier.setdefault(key, []).append(node.id)
            if node.provenance is not None:
                view.by_record[node.provenance.record_id] = node.id
        for edge in graph.relationships:
            view.out_edges.setdefault(edge.start_id, []).append(edge)
            view.in_edges.setdefault(edge.end_id, []).append(edge)
        return view

    def neighbours(self, node_id: str) -> list[tuple[GraphRelationship, str, str]]:
        """Return the edges leaving and entering a node, in a stable order."""
        found: list[tuple[GraphRelationship, str, str]] = []
        for edge in self.out_edges.get(node_id, ()):
            found.append((edge, edge.end_id, "out"))
        for edge in self.in_edges.get(node_id, ()):
            found.append((edge, edge.start_id, "in"))
        found.sort(key=lambda item: (item[0].relationship_type.value, item[1], item[0].key))
        return found


def _identifier_keys(node: GraphNode) -> tuple[str, ...]:
    """Return every string a node can be looked up by, lower-cased."""
    keys = [node.id, node.canonical_id, node.source_id]
    attack_id = node.properties.get("attackId")
    if attack_id:
        keys.append(attack_id)
    if node.name:
        keys.append(node.name)
    return tuple(dict.fromkeys(key.strip().lower() for key in keys if key and key.strip()))


@final
class KnowledgeGraphRetriever:
    """Retrieves chunks by walking the knowledge graph."""

    __slots__ = ("_view", "_chunks", "_settings")

    def __init__(
        self,
        graph: KnowledgeGraph,
        chunks: ChunkSource,
        settings: GraphRagSettings,
    ) -> None:
        """Build the adjacency view once and hold it for later queries."""
        self._view = GraphView.of(graph)
        self._chunks = chunks
        self._settings = settings

    @property
    def node_count(self) -> int:
        """Return how many nodes the view holds."""
        return len(self._view.nodes)

    def retrieve(
        self,
        query: RetrievalQuery,
        limit: int,
    ) -> tuple[tuple[Candidate, ...], tuple[SeedReport, ...]]:
        """Return graph candidates and the report of what the entities resolved to."""
        seeds, reports = self._seeds(query)
        if not seeds:
            return (), reports

        max_hops = query.max_hops if query.max_hops is not None else self._settings.max_hops
        reached = self._walk(seeds, max_hops)

        admits = query_predicate(query)
        candidates: list[Candidate] = []
        for node_id, (hops, path) in reached.items():
            node = self._view.nodes.get(node_id)
            if node is None or node.provenance is None:
                continue
            for chunk in self._chunks.chunks_of_record(node.provenance.record_id):
                if admits is not None and not admits(chunk):
                    continue
                candidates.append(
                    Candidate(
                        chunk=chunk,
                        evidence=(
                            RetrievalEvidence(
                                method=RetrievalMethod.GRAPH,
                                match_kind=(
                                    MatchKind.GRAPH_SEED if hops == 0 else MatchKind.GRAPH_NEIGHBOUR
                                ),
                                detail=f"node={node_id} hops={hops}",
                                matched_entities=(node.canonical_id,),
                                graph_path=path,
                                hops=hops,
                                raw_score=1.0 / (1 + hops),
                            ),
                        ),
                    )
                )
                if len(candidates) >= limit:
                    return tuple(candidates), reports
        return tuple(candidates), reports

    def _seeds(self, query: RetrievalQuery) -> tuple[tuple[str, ...], tuple[SeedReport, ...]]:
        """Return the seed nodes, and what every named entity resolved to."""
        seeds: list[str] = []
        reports: list[SeedReport] = []
        for value in query.all_identifiers:
            token = value.strip().lower()
            if not token:
                continue
            matches = self._view.by_identifier.get(token, [])
            if not matches:
                reports.append(
                    SeedReport(
                        value=value,
                        status=SeedStatus.UNRESOLVED.value,
                        note="no node carries this identifier",
                    )
                )
                continue
            if len(matches) > 1:
                reports.append(
                    SeedReport(
                        value=value,
                        status=SeedStatus.AMBIGUOUS.value,
                        node_ids=tuple(matches),
                        note=f"{len(matches)} nodes carry this identifier; none chosen",
                    )
                )
                continue
            reports.append(
                SeedReport(
                    value=value,
                    status=SeedStatus.RESOLVED.value,
                    node_ids=(matches[0],),
                )
            )
            seeds.append(matches[0])
        return tuple(dict.fromkeys(seeds)), tuple(reports)

    def _walk(
        self,
        seeds: tuple[str, ...],
        max_hops: int,
    ) -> dict[str, tuple[int, tuple[GraphPathStep, ...]]]:
        """Return every node within the hop bound, with the path that reached it."""
        reached: dict[str, tuple[int, tuple[GraphPathStep, ...]]] = {}
        queue: deque[tuple[str, int, tuple[GraphPathStep, ...]]] = deque()
        for seed in seeds:
            if seed in self._view.nodes:
                reached[seed] = (0, ())
                queue.append((seed, 0, ()))

        while queue:
            node_id, hops, path = queue.popleft()
            if hops >= max_hops:
                continue
            for edge, neighbour, direction in self._view.neighbours(node_id):
                if neighbour in reached:
                    continue
                step = GraphPathStep(
                    start_id=node_id,
                    relationship_type=edge.relationship_type.value,
                    end_id=neighbour,
                    direction=direction,
                )
                extended = (*path, step)
                reached[neighbour] = (hops + 1, extended)
                queue.append((neighbour, hops + 1, extended))
        return reached
