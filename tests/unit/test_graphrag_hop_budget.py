"""How the candidate budget is shared between hop levels.

The walk finds every node within the hop bound; the budget decides how many of
them become candidates. Spending it in the order the walk happens to produce —
every seed, then every hop-1 neighbour, then whatever is left — means a single
high-degree node can consume the whole budget at hop 1 and hop 2 is never read
at all. It is not that hop-2 evidence loses on score; it is never scored.

The corpus already contains nodes wide enough to do this, and the graph is
expected to gain more. So the budget is rationed by level instead: seeds first,
because a seed is the direct answer to what was asked, and then an equal share
to each remaining level, with anything a level does not use handed back to the
levels that can still spend it. A narrow graph therefore loses nothing — the
redistribution returns the whole budget — and a wide one stays bounded.

Nothing here is about any particular node type. A hub is a hub whether it is a
tactic, a technique, a widely-used schema field or something this corpus does
not hold yet.
"""

from __future__ import annotations

from src.graph.models import GraphNode, GraphRelationship, KnowledgeGraph
from src.graph.provenance import NodeProvenance, RelationshipProvenance
from src.graph.types import EdgeOrigin, NodeType, RelationshipType
from src.graphrag.config import GraphRagSettings
from src.graphrag.graph_retriever import KnowledgeGraphRetriever
from src.graphrag.models import Chunk, RetrievalQuery
from src.graphrag.types import MatchKind, SectionType
from src.knowledge.models.types import KnowledgeSource

SETTINGS = GraphRagSettings()


def provenance(record_id: str) -> NodeProvenance:
    """Return the provenance a node needs before it may produce a candidate."""
    return NodeProvenance(
        source=KnowledgeSource.ECS,
        source_id=record_id,
        record_id=record_id,
        dataset="probe.jsonl",
        line_number=1,
    )


def node(node_id: str, *, canonical_id: str | None = None, name: str | None = None) -> GraphNode:
    """Return one node, stating only what a case needs."""
    return GraphNode(
        id=node_id,
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id=canonical_id or node_id,
        canonical_id=canonical_id or node_id,
        name=name,
        properties={},
        provenance=provenance(node_id),
    )


def edge(start: str, end: str) -> GraphRelationship:
    """Return one edge, so a neighbour can be reached at a hop."""
    detail = RelationshipProvenance(
        source=KnowledgeSource.ECS,
        source_id=start,
        source_field="probe",
        source_location="probe",
        original_value=end,
        canonical_id=end,
        resolution_status="resolved",
        resolution_method="probe",
        origin=EdgeOrigin.RESOLVED_REFERENCE,
    )
    return GraphRelationship(
        key=f"{start}->{end}",
        relationship_type=RelationshipType.REFERENCES,
        start_id=start,
        end_id=end,
        provenance=detail,
    )


class OneChunkPerRecord:
    """A chunk source giving every record a single chunk."""

    def chunk(self, chunk_id: str) -> Chunk | None:
        """Return nothing; traversal reaches chunks by record, not by id."""
        return None

    def chunks_of_record(self, parent_record_id: str) -> tuple[Chunk, ...]:
        """Return the one chunk standing for a record."""
        return (
            Chunk(
                chunk_id=f"{parent_record_id}:chunk",
                parent_record_id=parent_record_id,
                source=KnowledgeSource.ECS,
                source_id=parent_record_id,
                section=SectionType.FIELD,
                text=parent_record_id,
            ),
        )


def retrieve(nodes, seeds, *, edges=(), limit=50, max_hops=None):
    """Return the candidates and reports one query produces over a small graph."""
    graph = KnowledgeGraph(nodes=tuple(nodes), relationships=tuple(edges))
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    query = RetrievalQuery(entity_ids=tuple(seeds), max_results=10, max_hops=max_hops)
    return retriever.retrieve(query, limit)


def hops_of(candidates) -> list[int]:
    """Return the hop count of every candidate, in the order returned."""
    return [item.evidence[0].hops for item in candidates]


def hub_graph(width: int, depth_each: int = 1):
    """Return a seed with `width` hop-1 neighbours, each carrying `depth_each` of its own.

    The shape that motivates the whole mechanism, and the one the corpus
    produces: the seed is the hub, hop 1 is wide enough to exhaust any budget,
    and the evidence that matters sits behind it at hop 2.
    """
    nodes = [node("seed")]
    edges = []
    for index in range(width):
        leaf = f"leaf{index:04d}"
        nodes.append(node(leaf))
        edges.append(edge("seed", leaf))
        for child in range(depth_each):
            grand = f"{leaf}-child{child}"
            nodes.append(node(grand))
            edges.append(edge(leaf, grand))
    return nodes, edges


# ------------------------------------------------------- 1-4. budget invariants


def test_a_hop_zero_seed_is_always_retained():
    """The direct answer to what was asked is never rationed away."""
    nodes, edges = hub_graph(width=500)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=10)

    assert hops_of(candidates)[0] == 0
    assert candidates[0].chunk.parent_record_id == "seed"


def test_hop_one_cannot_consume_the_entire_budget():
    """A 500-wide hub leaves room for the level behind it."""
    nodes, edges = hub_graph(width=500)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=60, max_hops=2)

    counts = {hop: hops_of(candidates).count(hop) for hop in (0, 1, 2)}
    assert counts[1] < 60
    assert counts[2] > 0


def test_hop_two_receives_capacity_behind_a_wide_hub():
    """The property the corpus needs: depth survives width."""
    nodes, edges = hub_graph(width=800, depth_each=1)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=90, max_hops=2)

    assert 2 in hops_of(candidates)


def test_the_total_never_exceeds_the_limit():
    """The budget is rationed, never raised."""
    nodes, edges = hub_graph(width=900)
    for limit in (1, 7, 50, 200):
        candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=limit, max_hops=2)
        assert len(candidates) <= limit


# ------------------------------------------------------------ 5-7. hop bounds


def test_max_hops_zero_returns_seeds_only():
    nodes, edges = hub_graph(width=50)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=50, max_hops=0)

    assert set(hops_of(candidates)) == {0}


def test_max_hops_one_never_reaches_hop_two():
    nodes, edges = hub_graph(width=50)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=50, max_hops=1)

    assert set(hops_of(candidates)) <= {0, 1}


def test_traversal_is_deterministic_across_runs():
    """Same graph, same query, same answer — the ordering rule is total."""
    nodes, edges = hub_graph(width=300)
    first, _ = retrieve(nodes, ["seed"], edges=edges, limit=80, max_hops=2)
    second, _ = retrieve(nodes, ["seed"], edges=edges, limit=80, max_hops=2)

    assert [c.chunk.chunk_id for c in first] == [c.chunk.chunk_id for c in second]


def test_candidates_are_returned_in_hop_order():
    """Rationing changes how much each level gets, not that nearer comes first."""
    nodes, edges = hub_graph(width=200)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=80, max_hops=2)

    assert hops_of(candidates) == sorted(hops_of(candidates))


# ------------------------------------------- 8-9. narrow graphs lose nothing


def test_a_narrow_graph_loses_no_candidate():
    """Redistribution hands back every share a level could not spend."""
    nodes, edges = hub_graph(width=3, depth_each=1)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=50, max_hops=2)

    # seed + 3 leaves at hop 1 + 3 children at hop 2 = 7 records, one chunk each.
    assert len(candidates) == 7


def test_a_graph_smaller_than_the_budget_is_returned_whole():
    nodes = [node("a"), node("b"), node("c")]
    edges = [edge("a", "b"), edge("b", "c")]
    candidates, _ = retrieve(nodes, ["a"], edges=edges, limit=50, max_hops=2)

    assert {c.chunk.parent_record_id for c in candidates} == {"a", "b", "c"}


def test_a_high_degree_graph_is_bounded():
    nodes, edges = hub_graph(width=2000)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=200, max_hops=2)

    assert len(candidates) == 200


# --------------------------------------- 10-14. existing behaviour unchanged


def test_an_unresolved_seed_is_still_reported_and_yields_nothing():
    present = [node("ecs:process.name", canonical_id="process.name")]
    candidates, reports = retrieve(present, ["T1562"])

    assert candidates == ()
    assert [(r.value, r.status) for r in reports] == [("T1562", "unresolved")]


def test_an_ambiguous_seed_still_chooses_nothing():
    nodes = [
        node("one", canonical_id="one", name="shared"),
        node("two", canonical_id="two", name="shared"),
    ]
    candidates, reports = retrieve(nodes, ["shared"])

    assert candidates == ()
    assert reports[0].status == "ambiguous"
    assert len(reports[0].node_ids) == 2


def test_f1a_exact_identifier_survives_rationing():
    """A seed matched on its identifier is still an exact match."""
    nodes, edges = hub_graph(width=400)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=60, max_hops=2)

    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_f1a_a_name_only_seed_is_still_a_graph_seed():
    nodes = [node("ds", canonical_id="enterprise:DS0007", name="Image")]
    candidates, _ = retrieve(nodes, ["Image"])

    assert candidates[0].evidence[0].match_kind is MatchKind.GRAPH_SEED


def test_f1b_matched_entities_still_carry_the_seed():
    nodes, edges = hub_graph(width=400)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=60, max_hops=2)

    assert "seed" in candidates[0].evidence[0].matched_entities


def test_a_neighbour_is_still_a_graph_neighbour():
    nodes, edges = hub_graph(width=5)
    candidates, _ = retrieve(nodes, ["seed"], edges=edges, limit=50, max_hops=2)
    beyond = [c for c in candidates if c.evidence[0].hops > 0]

    assert all(c.evidence[0].match_kind is MatchKind.GRAPH_NEIGHBOUR for c in beyond)


def test_an_ecs_field_seed_behaves_as_before():
    """C3's seeding path is untouched: one ECS field, one hop-0 candidate."""
    field = [node("ecs:event.action", canonical_id="event.action")]
    candidates, _ = retrieve(field, ["event.action"])

    assert len(candidates) == 1
    assert candidates[0].evidence[0].hops == 0
    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_several_seeds_are_all_retained():
    """Hop 0 is taken before any share is computed, so no seed is rationed out."""
    nodes = [node(f"f{i}", canonical_id=f"field{i}") for i in range(6)]
    candidates, _ = retrieve(nodes, [f"field{i}" for i in range(6)], limit=50)

    assert len(candidates) == 6
    assert set(hops_of(candidates)) == {0}


# ------------------------------------------------------- 15. weights untouched


def test_the_ranking_weights_are_untouched():
    weights = GraphRagSettings().weights

    assert (weights.exact_identifier, weights.entity_match, weights.graph) == (0.30, 0.20, 0.20)
    assert (weights.lexical, weights.source) == (0.15, 0.07)
    assert (weights.distance, weights.section) == (0.05, 0.03)
    assert GraphRagSettings().candidate_limit == 200
    assert GraphRagSettings().max_hops == 2
