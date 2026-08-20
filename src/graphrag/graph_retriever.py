"""Graph retrieval.

Answers a query by walking the Stage-12 knowledge graph.

The graph is used, never rebuilt and never re-derived. An adjacency view is
computed once from the graph object and reused for every query, so a lookup does
not scan 13,000 nodes.

Seeding is the only place identifiers meet the graph, and it is where the
corpus's honesty is preserved. An identifier that no node carries is reported
unresolved and contributes nothing, and no node is manufactured for it. An
identifier several nodes carry is reported ambiguous with every candidate listed
and **no seed chosen**, so ``M1013`` never silently becomes the enterprise one.

One narrow exception sits between those two, and it invents nothing either.
Where ATT&CK has revoked an identifier in favour of exactly one successor the
corpus already holds, the walk starts at that successor's node and the seed is
reported ``redirected``, carrying both identifiers. ``T1562`` still finds no
node of its own; what it finds is ``T1685``, which ATT&CK says is the same
subject renumbered, and the report says exactly that rather than claiming the
rule named ``T1685``. See :mod:`src.graphrag.attack_redirects`.

Every walk is bounded by the configured hop limit. There is no unbounded
traversal, and the frontier stops expanding once the limit is reached.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import islice
from typing import final

from src.graph.models import GraphNode, GraphRelationship, KnowledgeGraph

from .attack_redirects import redirect_for
from .config import GraphRagSettings
from .filters import query_predicate
from .interfaces import ChunkSource
from .models import Candidate, Chunk, RetrievalQuery
from .provenance import GraphPathStep, RetrievalEvidence, SeedReport, SuccessorRecord
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


def _identifiers_of(node: GraphNode) -> tuple[str, ...]:
    """Return the strings that *identify* a node, lower-cased.

    Its name is not one of them. A name is what a record is called, and two
    records may be called the same thing — the ATT&CK data source named ``Image``
    and the Sysmon field of that name are different subjects. An identifier says
    which record this is; a name says only what it is called.
    """
    attack_id = node.properties.get("attackId", "")
    keys = (node.id, node.canonical_id, node.source_id, attack_id)
    return tuple(dict.fromkeys(key.strip().lower() for key in keys if key and key.strip()))


def _identifier_keys(node: GraphNode) -> tuple[str, ...]:
    """Return every string a node can be looked up by, lower-cased.

    The name is included, because a caller may reasonably name a record rather
    than identify it and still mean it. What the lookup may not do is treat the
    two as the same kind of evidence, which is why the identifiers are stated
    apart by :func:`_identifiers_of`.
    """
    keys = list(_identifiers_of(node))
    if node.name and node.name.strip():
        keys.append(node.name.strip().lower())
    return tuple(dict.fromkeys(keys))


def _matched_by(
    node: GraphNode,
    seed: str | None,
    hops: int,
) -> tuple[MatchKind, tuple[str, ...]]:
    """Return how a candidate matched, and the entities its evidence may claim.

    Three answers, and the middle one is why this is a function rather than an
    expression:

    * A seed that is one of the node's identifiers is an **exact identifier**
      match. The record does not merely mention the thing asked about — it *is*
      that thing, which is the strongest statement retrieval can make.
    * A seed that reached the node only through its name stays a **graph seed**.
      Starting the walk there was right, but the query named a word rather than
      a record, and thousands of nodes in this corpus answer to a name they do
      not otherwise identify as.
    * Anything reached by walking is a **graph neighbour**, whatever it is
      called. A hop is a relationship, not an identity.

    The entities follow the same rule. An exact match reports the seed first,
    because that is what the query asked with and what ranking compares against,
    and keeps the node's canonical id behind it so the record's own identity
    survives. Every other case reports the canonical id alone: nothing about the
    seed was confirmed, and repeating it would assert a match never made.
    """
    if hops > 0:
        return MatchKind.GRAPH_NEIGHBOUR, (node.canonical_id,)
    if seed is not None and seed.strip().lower() in _identifiers_of(node):
        return MatchKind.EXACT_IDENTIFIER, tuple(dict.fromkeys((seed, node.canonical_id)))
    return MatchKind.GRAPH_SEED, (node.canonical_id,)


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
        reached = self._walk(tuple(seeds), max_hops)

        return self._collect(reached, seeds, query_predicate(query), limit), reports

    def _collect(
        self,
        reached: Mapping[str, tuple[int, tuple[GraphPathStep, ...]]],
        seeds: Mapping[str, str],
        admits: Callable[[Chunk], bool] | None,
        limit: int,
    ) -> tuple[Candidate, ...]:
        """Return the candidates the walk produced, rationing the budget by hop.

        The walk finds every node inside the hop bound; this decides which of
        them the budget can afford. Spending it in walk order — every seed, then
        every hop-1 neighbour, then whatever survives — lets one wide level
        exhaust the budget before the next is read at all. That is not hop-2
        evidence losing on score; it is hop-2 evidence never being scored, and
        the corpus already holds nodes wide enough to cause it.

        So each level is given a share instead:

        * **Hop 0 is never rationed.** A seed is the direct answer to what was
          asked, and there are only ever as many as the query named identifiers.
        * **Every deeper level receives an equal share** of what remains.
        * **Anything a level cannot spend goes back**, and the levels that still
          have candidates take it in hop order.

        The redistribution is what keeps a narrow graph whole: when no level
        fills its share, every candidate is returned and the rationing has cost
        nothing. A wide graph stays inside the same budget it always had — the
        limit is shared differently, never raised.

        The streams are generators, so the second pass resumes exactly where the
        first stopped and no record is chunked twice. Order is by hop, as it has
        always been, and the sort is stable, so two runs over one graph return
        one answer.
        """
        levels: dict[int, list[tuple[str, int, tuple[GraphPathStep, ...]]]] = {}
        for node_id, (hops, path) in reached.items():
            levels.setdefault(hops, []).append((node_id, hops, path))

        streams = {
            hops: self._candidates_of(entries, seeds, admits)
            for hops, entries in sorted(levels.items())
        }
        collected: list[Candidate] = list(islice(streams.get(0, iter(())), limit))

        deeper = [hops for hops in streams if hops > 0]
        if deeper:
            share = max(0, (limit - len(collected)) // len(deeper))
            for hops in deeper:
                collected.extend(islice(streams[hops], share))
            for hops in streams:
                if len(collected) >= limit:
                    break
                collected.extend(islice(streams[hops], limit - len(collected)))

        collected.sort(key=lambda candidate: candidate.evidence[0].hops)
        return tuple(collected[:limit])

    def _candidates_of(
        self,
        entries: Sequence[tuple[str, int, tuple[GraphPathStep, ...]]],
        seeds: Mapping[str, str],
        admits: Callable[[Chunk], bool] | None,
    ) -> Iterator[Candidate]:
        """Yield every candidate one hop level produces, in walk order."""
        for node_id, hops, path in entries:
            node = self._view.nodes.get(node_id)
            if node is None or node.provenance is None:
                continue
            kind, matched = _matched_by(node, seeds.get(node_id) if hops == 0 else None, hops)
            for chunk in self._chunks.chunks_of_record(node.provenance.record_id):
                if admits is not None and not admits(chunk):
                    continue
                yield Candidate(
                    chunk=chunk,
                    evidence=(
                        RetrievalEvidence(
                            method=RetrievalMethod.GRAPH,
                            match_kind=kind,
                            detail=f"node={node_id} hops={hops}",
                            matched_entities=matched,
                            graph_path=path,
                            hops=hops,
                            raw_score=1.0 / (1 + hops),
                        ),
                    ),
                )

    def _seeds(
        self,
        query: RetrievalQuery,
    ) -> tuple[Mapping[str, str], tuple[SeedReport, ...]]:
        """Return each seed node with the value that reached it, and every report.

        The value is kept beside the node rather than discarded, because what a
        candidate may honestly claim depends on it: a node reached by its
        identifier is an exact match and a node reached by its name is not, and
        once the walk is over that distinction can no longer be recovered.
        """
        seeds: dict[str, str] = {}
        reports: list[SeedReport] = []
        for value in query.all_identifiers:
            token = value.strip().lower()
            if not token:
                continue
            matches = self._view.by_identifier.get(token, [])
            if not matches:
                report = self._redirected(value)
                reports.append(report)
                if report.status == SeedStatus.REDIRECTED.value:
                    seeds.setdefault(report.node_ids[0], value)
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
            seeds.setdefault(matches[0], value)
        return seeds, tuple(reports)

    def _redirected(self, value: str) -> SeedReport:
        """Return the report for an identifier no node carries.

        Unresolved is still the answer for almost everything, and it is the
        answer this returns unless every condition for following a redirect
        holds at once: ATT&CK revoked the identifier, it revoked it in favour of
        exactly one successor, and exactly one node in *this* corpus carries
        that successor.

        Each failure is reported as what it is rather than collapsed into one
        outcome. A revocation with several successors is **ambiguous** — the
        candidates are listed and none is chosen, which is the same promise
        :meth:`_seeds` already makes for an identifier several nodes carry. A
        successor the corpus does not hold, or holds twice, leaves the reference
        exactly where it was: reaching nothing, and saying so.

        No node is created in any branch. A redirect is a way of looking up a
        record the corpus already has, never a way of inventing one.
        """
        redirect = redirect_for(value)
        if redirect is None:
            return SeedReport(
                value=value,
                status=SeedStatus.UNRESOLVED.value,
                note="no node carries this identifier",
            )
        if not redirect.is_one_to_one:
            listed = ", ".join(redirect.successors)
            return SeedReport(
                value=value,
                status=SeedStatus.AMBIGUOUS.value,
                node_ids=self._nodes_of(redirect.successors),
                note=(
                    f"ATT&CK revoked this identifier in favour of {len(redirect.successors)} "
                    f"identifiers ({listed}); none chosen"
                ),
            )
        successor = redirect.successor
        matches = self._view.by_identifier.get(successor.strip().lower(), [])
        if not matches:
            return SeedReport(
                value=value,
                status=SeedStatus.UNRESOLVED.value,
                note=(
                    f"no node carries this identifier; ATT&CK revoked it in favour of "
                    f"{successor}, which no node carries either"
                ),
            )
        if len(matches) > 1:
            return SeedReport(
                value=value,
                status=SeedStatus.AMBIGUOUS.value,
                node_ids=tuple(matches),
                note=(
                    f"ATT&CK revoked this identifier in favour of {successor}, which "
                    f"{len(matches)} nodes carry; none chosen"
                ),
            )
        return SeedReport(
            value=value,
            status=SeedStatus.REDIRECTED.value,
            node_ids=(matches[0],),
            note=f"ATT&CK revoked this identifier in favour of {successor}",
            resolved_value=successor,
            resolved_record=self._record_of(matches[0], successor),
        )

    def _record_of(self, node_id: str, identifier: str) -> SuccessorRecord | None:
        """Return the successor node's own knowledge record, or ``None``.

        Read from the same chunk source the walk already retrieves from, so
        this is the record the corpus holds rather than a second copy of it.
        Nothing is created: a node without provenance, or one whose record the
        index holds no chunk for, yields ``None`` and the redirect simply
        carries no record.
        """
        node = self._view.nodes.get(node_id)
        if node is None or node.provenance is None:
            return None
        chunks = self._chunks.chunks_of_record(node.provenance.record_id)
        if not chunks:
            return None
        first = chunks[0]
        return SuccessorRecord(
            record_id=node.provenance.record_id,
            identifier=identifier,
            name=(node.name or identifier).strip(),
            text="\n\n".join(chunk.text for chunk in chunks),
            chunk_ids=tuple(chunk.chunk_id for chunk in chunks),
            source=first.source,
            location=first.provenance.location if first.provenance else "",
        )

    def _nodes_of(self, identifiers: Sequence[str]) -> tuple[str, ...]:
        """Return every node any of a set of identifiers reaches, in first-seen order."""
        found: list[str] = []
        for identifier in identifiers:
            for node_id in self._view.by_identifier.get(identifier.strip().lower(), []):
                if node_id not in found:
                    found.append(node_id)
        return tuple(found)

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
