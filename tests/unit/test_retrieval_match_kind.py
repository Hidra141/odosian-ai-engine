"""Unit tests for MatchKind assignment in retrieval (Phase 3B - F1).

Covers:
- canonical_id exact match -> EXACT_IDENTIFIER
- source_id exact match -> EXACT_IDENTIFIER
- node id exact match -> EXACT_IDENTIFIER
- attackId exact match -> EXACT_IDENTIFIER
- case-insensitive exact match -> EXACT_IDENTIFIER
- name-only match -> remains GRAPH_SEED
- hops > 0 -> remains GRAPH_NEIGHBOUR
- partial / non-exact identifier match -> remains GRAPH_SEED
- ambiguous seed behavior remains unchanged
- lexical exact behavior remains unchanged
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from src.graph.models import GraphNode, GraphRelationship, KnowledgeGraph
from src.graph.provenance import NodeProvenance, RelationshipProvenance
from src.graph.types import EdgeOrigin, NodeType, RelationshipType
from src.graphrag.config import GraphRagSettings
from src.graphrag.graph_retriever import KnowledgeGraphRetriever
from src.graphrag.models import Chunk, RetrievalQuery
from src.graphrag.text_index import TextIndex
from src.graphrag.text_retriever import LexicalTextRetriever
from src.graphrag.types import MatchKind, SectionType
from src.knowledge.models.types import KnowledgeSource


@dataclass(frozen=True, slots=True)
class InMemoryChunkSource:
    """A simple chunk source for unit tests."""

    chunks_by_record: dict[str, tuple[Chunk, ...]]

    def chunk(self, chunk_id: str) -> Chunk | None:
        for chunks in self.chunks_by_record.values():
            for c in chunks:
                if c.chunk_id == chunk_id:
                    return c
        return None

    def chunks_of_record(self, parent_record_id: str) -> tuple[Chunk, ...]:
        return self.chunks_by_record.get(parent_record_id, ())


def _create_chunk(record_id: str, text: str = "some text") -> Chunk:
    return Chunk(
        chunk_id=f"{record_id}:chunk:001",
        parent_record_id=record_id,
        source=KnowledgeSource.ECS,
        source_id=record_id,
        section=SectionType.FIELD,
        text=text,
    )


def _node_prov(record_id: str, source: KnowledgeSource = KnowledgeSource.ECS) -> NodeProvenance:
    return NodeProvenance(
        source=source,
        source_id=record_id,
        record_id=record_id,
        dataset="test_ds",
        line_number=1,
    )


def _rel_prov(source: KnowledgeSource = KnowledgeSource.ECS) -> RelationshipProvenance:
    return RelationshipProvenance(
        source=source,
        source_id="src_1",
        source_field="related",
        source_location="test.jsonl:1",
        original_value="rel_val",
        canonical_id="can_id",
        resolution_status="resolved",
        resolution_method="exact",
        origin=EdgeOrigin.RESOLVED_REFERENCE,
    )


def _build_test_retriever(
    nodes: tuple[GraphNode, ...],
    relationships: tuple[GraphRelationship, ...] = (),
    chunks: dict[str, tuple[Chunk, ...]] | None = None,
) -> KnowledgeGraphRetriever:
    graph = KnowledgeGraph(nodes=nodes, relationships=relationships)
    chunk_source = InMemoryChunkSource(chunks or {})
    return KnowledgeGraphRetriever(graph, chunk_source, GraphRagSettings())


def test_canonical_id_exact_match_receives_exact_identifier() -> None:
    node = GraphNode(
        id="ecs:field:process.name",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="process.name",
        canonical_id="process.name",
        name="Process Name",
        provenance=_node_prov("rec_process_name"),
    )
    chunk = _create_chunk("rec_process_name", "process.name details")
    retriever = _build_test_retriever((node,), chunks={"rec_process_name": (chunk,)})

    query = RetrievalQuery(canonical_fields=("process.name",))
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 1
    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER
    assert candidates[0].evidence[0].hops == 0


def test_source_id_exact_match_receives_exact_identifier() -> None:
    node = GraphNode(
        id="derived:custom:node1",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="custom.source.id",
        canonical_id="canonical.different",
        name="Custom Field",
        provenance=_node_prov("rec_custom"),
    )
    chunk = _create_chunk("rec_custom")
    retriever = _build_test_retriever((node,), chunks={"rec_custom": (chunk,)})

    query = RetrievalQuery(entity_ids=("custom.source.id",))
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 1
    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_node_id_exact_match_receives_exact_identifier() -> None:
    node = GraphNode(
        id="ecs:field:process.name",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="process.name",
        canonical_id="process.name",
        provenance=_node_prov("rec_proc"),
    )
    chunk = _create_chunk("rec_proc")
    retriever = _build_test_retriever((node,), chunks={"rec_proc": (chunk,)})

    query = RetrievalQuery(entity_ids=("ecs:field:process.name",))
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 1
    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_attack_id_exact_match_receives_exact_identifier() -> None:
    node = GraphNode(
        id="mitre:technique:enterprise-attack:T1059.001",
        node_type=NodeType.TECHNIQUE,
        source=KnowledgeSource.MITRE,
        source_id="enterprise-attack:T1059.001",
        canonical_id="enterprise-attack:T1059.001",
        properties=MappingProxyType({"attackId": "T1059.001"}),
        provenance=_node_prov("rec_mitre", source=KnowledgeSource.MITRE),
    )
    chunk = _create_chunk("rec_mitre")
    retriever = _build_test_retriever((node,), chunks={"rec_mitre": (chunk,)})

    query = RetrievalQuery(entity_ids=("T1059.001",))
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 1
    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_case_insensitive_exact_match() -> None:
    node = GraphNode(
        id="ecs:field:process.name",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="process.name",
        canonical_id="process.name",
        provenance=_node_prov("rec_proc"),
    )
    chunk = _create_chunk("rec_proc")
    retriever = _build_test_retriever((node,), chunks={"rec_proc": (chunk,)})

    query = RetrievalQuery(canonical_fields=("PROCESS.NAME",))
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 1
    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_name_only_match_remains_graph_seed() -> None:
    node = GraphNode(
        id="ecs:field:process.executable",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="process.executable",
        canonical_id="process.executable",
        name="Image",
        provenance=_node_prov("rec_img"),
    )
    chunk = _create_chunk("rec_img")
    retriever = _build_test_retriever((node,), chunks={"rec_img": (chunk,)})

    query = RetrievalQuery(canonical_fields=("Image",))
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 1
    assert candidates[0].evidence[0].match_kind is MatchKind.GRAPH_SEED
    assert candidates[0].evidence[0].hops == 0


def test_hops_greater_than_zero_remains_graph_neighbour() -> None:
    node_a = GraphNode(
        id="ecs:field:process.name",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="process.name",
        canonical_id="process.name",
        provenance=_node_prov("rec_a"),
    )
    node_b = GraphNode(
        id="ecs:field:process.pid",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="process.pid",
        canonical_id="process.pid",
        provenance=_node_prov("rec_b"),
    )
    edge = GraphRelationship(
        key="edge1",
        relationship_type=RelationshipType.REFERENCES,
        start_id=node_a.id,
        end_id=node_b.id,
        provenance=_rel_prov(),
    )
    chunk_a = _create_chunk("rec_a")
    chunk_b = _create_chunk("rec_b")
    retriever = _build_test_retriever(
        (node_a, node_b),
        (edge,),
        chunks={"rec_a": (chunk_a,), "rec_b": (chunk_b,)},
    )

    query = RetrievalQuery(canonical_fields=("process.name",), max_hops=1)
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 2
    by_record = {c.chunk.parent_record_id: c for c in candidates}
    assert by_record["rec_a"].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER
    assert by_record["rec_b"].evidence[0].match_kind is MatchKind.GRAPH_NEIGHBOUR
    assert by_record["rec_b"].evidence[0].hops == 1


def test_partial_match_remains_graph_seed() -> None:
    """When a node was reached without direct exact identifier match in query tokens."""
    node = GraphNode(
        id="ecs:field:process.name",
        node_type=NodeType.ECS_FIELD,
        source=KnowledgeSource.ECS,
        source_id="process.name",
        canonical_id="process.name",
        name="Process Name",
        provenance=_node_prov("rec_proc"),
    )
    chunk = _create_chunk("rec_proc")
    # If the retriever is queried with an identifier that does not match
    # id/canonical/source/attackId but only matches name (or partial alias in name)
    retriever = _build_test_retriever((node,), chunks={"rec_proc": (chunk,)})
    query = RetrievalQuery(canonical_fields=("Process Name",))
    candidates, _ = retriever.retrieve(query, limit=10)

    assert len(candidates) == 1
    assert candidates[0].evidence[0].match_kind is MatchKind.GRAPH_SEED
    assert candidates[0].evidence[0].hops == 0


def test_ambiguous_seed_behavior_remains_unchanged() -> None:
    node1 = GraphNode(
        id="mitre:technique:enterprise-attack:T1000",
        node_type=NodeType.TECHNIQUE,
        source=KnowledgeSource.MITRE,
        source_id="enterprise-attack:T1000",
        canonical_id="enterprise-attack:T1000",
        name="Ambiguous Technique",
        properties=MappingProxyType({"attackId": "T1000"}),
    )
    node2 = GraphNode(
        id="mitre:technique:ics-attack:T1000",
        node_type=NodeType.TECHNIQUE,
        source=KnowledgeSource.MITRE,
        source_id="ics-attack:T1000",
        canonical_id="ics-attack:T1000",
        name="Ambiguous Technique ICS",
        properties=MappingProxyType({"attackId": "T1000"}),
    )
    retriever = _build_test_retriever((node1, node2))

    query = RetrievalQuery(entity_ids=("T1000",))
    candidates, reports = retriever.retrieve(query, limit=10)

    assert candidates == ()
    assert len(reports) == 1
    assert reports[0].status == "ambiguous"


def test_lexical_exact_behavior_remains_unchanged() -> None:
    chunk1 = _create_chunk("rec1", "This chunk mentions powershell.exe in detail.")
    chunk2 = _create_chunk("rec2", "This chunk talks about command execution generally.")
    index = TextIndex(GraphRagSettings())
    index.build((chunk1, chunk2))
    retriever = LexicalTextRetriever(index=index)

    query = RetrievalQuery(text="powershell", entity_ids=("powershell.exe",))
    candidates = retriever.retrieve(query, limit=10)

    assert len(candidates) >= 1
    by_id = {c.chunk.chunk_id: c for c in candidates}
    if "rec1:chunk:001" in by_id:
        assert by_id["rec1:chunk:001"].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER
