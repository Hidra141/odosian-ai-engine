"""Why a graph candidate matched, and what it says matched.

A seed reaches the graph through the identifier index, which registers a node by
its identifiers *and* by its name. Those are not the same claim. A node found
because the query named its identifier is an exact match on a fact; a node found
because the query happened to spell its name is a coincidence of vocabulary —
``Image`` is a Sysmon field and also the name of an ATT&CK data source, and only
one of those is what a rule meant.

The evidence a candidate carries has to tell them apart, because ranking reads
it: the exact-identifier component is the largest weight there is, and the
entity component compares what matched against what the query asked with.
Evidence reporting the node's own canonical id rather than the seed answers a
question nobody asked.

These tests build small graphs rather than the corpus, so each case states
exactly one situation: an identifier match, a name-only match, a neighbour, a
difference of case, an ambiguity.
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


def node(
    node_id: str,
    *,
    canonical_id: str,
    source_id: str = "",
    name: str | None = None,
    attack_id: str = "",
    node_type: NodeType = NodeType.ECS_FIELD,
) -> GraphNode:
    """Return one node, stating only what a case needs."""
    return GraphNode(
        id=node_id,
        node_type=node_type,
        source=KnowledgeSource.ECS,
        source_id=source_id or canonical_id,
        canonical_id=canonical_id,
        name=name,
        properties={"attackId": attack_id} if attack_id else {},
        provenance=provenance(node_id),
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


def retrieve(nodes, seeds, *, edges=()):
    """Return the candidates and reports one query produces over a small graph."""
    graph = KnowledgeGraph(nodes=tuple(nodes), relationships=tuple(edges))
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    return retriever.retrieve(RetrievalQuery(entity_ids=tuple(seeds), max_results=10), 50)


def only(candidates):
    """Return the single evidence entry of a single candidate."""
    assert len(candidates) == 1
    assert len(candidates[0].evidence) == 1
    return candidates[0].evidence[0]


# --------------------------------------------------------- identifier matching


def test_a_canonical_identifier_seed_is_an_exact_identifier_match():
    nodes = [node("ecs:process.name", canonical_id="process.name")]
    assert only(retrieve(nodes, ["process.name"])[0]).match_kind is (
        MatchKind.EXACT_IDENTIFIER
    )


def test_a_source_identifier_seed_is_an_exact_identifier_match():
    nodes = [node("n", canonical_id="enterprise:x", source_id="x")]
    assert only(retrieve(nodes, ["x"])[0]).match_kind is MatchKind.EXACT_IDENTIFIER


def test_a_node_identifier_seed_is_an_exact_identifier_match():
    nodes = [node("ecs:process.name", canonical_id="process.name")]
    assert only(retrieve(nodes, ["ecs:process.name"])[0]).match_kind is (
        MatchKind.EXACT_IDENTIFIER
    )


def test_identifier_matching_ignores_case():
    """The index lower-cases its keys, so the confirmation must too."""
    nodes = [node("ecs:process.name", canonical_id="process.name")]
    assert only(retrieve(nodes, ["PROCESS.NAME"])[0]).match_kind is (
        MatchKind.EXACT_IDENTIFIER
    )


def test_an_attack_identifier_seed_is_an_exact_identifier_match():
    nodes = [
        node(
            "mitre:Technique:enterprise:T1083",
            canonical_id="enterprise:T1083",
            source_id="enterprise:T1083",
            attack_id="T1083",
            name="File and Directory Discovery",
            node_type=NodeType.TECHNIQUE,
        )
    ]
    assert only(retrieve(nodes, ["T1083"])[0]).match_kind is MatchKind.EXACT_IDENTIFIER


# ------------------------------------------------------------ name-only matches


def test_a_name_only_seed_stays_a_graph_seed():
    """``Image`` names a Sysmon field and an ATT&CK data source. Only one is meant."""
    nodes = [
        node(
            "mitre:DataSource:enterprise:DS0007",
            canonical_id="enterprise:DS0007",
            source_id="enterprise:DS0007",
            attack_id="DS0007",
            name="Image",
            node_type=NodeType.DATA_SOURCE,
        )
    ]
    assert only(retrieve(nodes, ["Image"])[0]).match_kind is MatchKind.GRAPH_SEED


def test_a_name_only_seed_reports_no_matching_identifier():
    nodes = [
        node(
            "n",
            canonical_id="enterprise:DS0007",
            source_id="enterprise:DS0007",
            name="Image",
        )
    ]
    assert only(retrieve(nodes, ["Image"])[0]).matched_entities == ("enterprise:DS0007",)


def test_a_name_that_is_also_an_identifier_still_qualifies():
    """An ECS field's name and identifier are one string; that is not a collision."""
    nodes = [node("ecs:process.name", canonical_id="process.name", name="process.name")]
    assert only(retrieve(nodes, ["process.name"])[0]).match_kind is (
        MatchKind.EXACT_IDENTIFIER
    )


# ---------------------------------------------------------------- neighbours


def test_a_neighbour_is_never_an_exact_identifier_match():
    nodes = [
        node("seed", canonical_id="seed"),
        node("neighbour", canonical_id="neighbour"),
    ]
    found, _ = retrieve(nodes, ["seed"], edges=[edge("seed", "neighbour")])
    assert {item.evidence[0].match_kind: item.evidence[0].hops for item in found} == {
        MatchKind.EXACT_IDENTIFIER: 0,
        MatchKind.GRAPH_NEIGHBOUR: 1,
    }


def test_a_neighbour_reports_its_own_canonical_id():
    nodes = [
        node("seed", canonical_id="seed"),
        node("neighbour", canonical_id="neighbour"),
    ]
    found, _ = retrieve(nodes, ["seed"], edges=[edge("seed", "neighbour")])
    walked = next(item for item in found if item.evidence[0].hops == 1)
    assert walked.evidence[0].matched_entities == ("neighbour",)


# ------------------------------------------------------------ what evidence says


def test_the_evidence_reports_the_seed_that_matched():
    nodes = [
        node(
            "mitre:Technique:enterprise:T1083",
            canonical_id="enterprise:T1083",
            source_id="enterprise:T1083",
            attack_id="T1083",
            node_type=NodeType.TECHNIQUE,
        )
    ]
    matched = only(retrieve(nodes, ["T1083"])[0]).matched_entities
    assert matched[0] == "T1083"


def test_the_evidence_keeps_the_canonical_id_beside_the_seed():
    """The node's own identity is not discarded, only placed behind the seed."""
    nodes = [
        node(
            "n",
            canonical_id="enterprise:T1083",
            source_id="enterprise:T1083",
            attack_id="T1083",
        )
    ]
    assert only(retrieve(nodes, ["T1083"])[0]).matched_entities == (
        "T1083",
        "enterprise:T1083",
    )


def test_a_seed_equal_to_the_canonical_id_is_reported_once():
    nodes = [node("ecs:process.name", canonical_id="process.name")]
    assert only(retrieve(nodes, ["process.name"])[0]).matched_entities == (
        "process.name",
    )


def test_a_qualifying_seed_fabricates_no_other_evidence():
    """One reason, one entry, and the route is still the graph."""
    nodes = [node("ecs:process.name", canonical_id="process.name")]
    evidence = only(retrieve(nodes, ["process.name"])[0])
    assert evidence.hops == 0
    assert evidence.raw_score == 1.0
    assert evidence.graph_path == ()
    assert evidence.method.value == "graph"


# -------------------------------------------------- ambiguity and absence


def test_an_ambiguous_seed_still_chooses_nothing():
    nodes = [
        node("a", canonical_id="shared", source_id="a"),
        node("b", canonical_id="shared", source_id="b"),
    ]
    found, reports = retrieve(nodes, ["shared"])
    assert found == ()
    assert [(item.value, item.status) for item in reports] == [("shared", "ambiguous")]


def test_an_unresolved_seed_is_reported_and_manufactures_nothing():
    found, reports = retrieve([node("n", canonical_id="present")], ["absent"])
    assert found == ()
    assert [(item.value, item.status) for item in reports] == [("absent", "unresolved")]
