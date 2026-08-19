"""Asking each route in the vocabulary it can answer in.

A rule names a field once and the engine has to ask about it twice, because the
two routes are keyed by different things. The graph is keyed by what the corpus
calls a field, so it must be asked ``process.executable``. The index holds what
rules wrote, so it must be asked ``Image``: the corpus spells that field
``Image`` in its own Sigma records and ``process.executable`` in none of them,
and a lexical question in the wrong vocabulary does not return less — it returns
a different corpus. Asked in ECS names, a Sigma rule's own field list retrieves
Elastic rules and ECS field documentation; asked in Sigma names, it retrieves
the Sigma rules that detect the same behaviour.

So :class:`RetrievalQuery` states both, and each route reads one. What must not
happen is either leaking into the other's job: a Sigma spelling that reached
graph seeding would find the ATT&CK data source named ``Image`` — a real node,
the wrong subject — and an ECS name that reached the index would ask the
question that lost the Sigma corpus in the first place.

These tests build small graphs and a small index rather than the corpus, so each
case states one situation, and they check the seams the separation runs through:
the query object, the lexical route, the graph route, and the three earlier
findings — F1A, F1B, C3, the Phase 3F tie-break and the Phase 4B hop budget —
that read the query and must not notice the change.
"""

from __future__ import annotations

from src.application.retrieval import rule_query
from src.context.models import RuleContext
from src.entities.models import Entity, ExtractedEntities
from src.entities.types import EntityType, RuleSection
from src.graph.models import GraphNode, GraphRelationship, KnowledgeGraph
from src.graph.provenance import NodeProvenance, RelationshipProvenance
from src.graph.types import EdgeOrigin, NodeType, RelationshipType
from src.graphrag.config import GraphRagSettings
from src.graphrag.graph_retriever import KnowledgeGraphRetriever
from src.graphrag.models import Candidate, Chunk, RetrievalQuery
from src.graphrag.ranking import DeterministicRanker
from src.graphrag.text_index import TextIndex
from src.graphrag.text_retriever import LexicalTextRetriever
from src.graphrag.types import MatchKind, RetrievalMethod, SectionType
from src.knowledge.models.types import KnowledgeSource
from src.mapping.entity_mapper import EntityMapper
from src.parser.types import RuleFormat

SETTINGS = GraphRagSettings()
MAPPER = EntityMapper()

ECS_FIELDS = frozenset(
    {
        "process.executable",
        "process.parent.executable",
        "process.command_line",
        "process.name",
        "event.code",
        "event.action",
        "file.path",
        "registry.path",
        "user.name",
    }
)


# ------------------------------------------------------------------ helpers


def field(name: str, source_field: str | None = None) -> Entity:
    """Return the entity a detection clause naming one field produces."""
    return Entity(
        entity_type=EntityType.FIELD,
        value=name,
        source_field=source_field if source_field is not None else name,
        location="detection.selection[0]",
        section=RuleSection.DETECTION,
        extractor="field",
    )


def reference(identifier: str) -> Entity:
    """Return the entity an ATT&CK tag produces."""
    return Entity(
        entity_type=EntityType.TAG,
        value=identifier,
        source_field="tags",
        location="tags[0]",
        section=RuleSection.TAGS,
        extractor="reference",
    )


def query_of(
    *entities: Entity,
    rule_format: RuleFormat = RuleFormat.SIGMA,
    text: str = "",
) -> RetrievalQuery:
    """Return the query a rule made of these entities asks the corpus."""
    mappings = MAPPER.map(
        ExtractedEntities(rule_format=rule_format, entities=tuple(entities))
    )
    return rule_query(
        RuleContext(query=text), mappings, top_k=10, ecs_fields=ECS_FIELDS
    )


def provenance(record_id: str, source: KnowledgeSource) -> NodeProvenance:
    """Return the provenance a node needs before it may produce a candidate."""
    return NodeProvenance(
        source=source,
        source_id=record_id,
        record_id=record_id,
        dataset="probe.jsonl",
        line_number=1,
    )


def node(
    node_id: str,
    *,
    canonical_id: str,
    name: str | None = None,
    attack_id: str = "",
    node_type: NodeType = NodeType.ECS_FIELD,
    source: KnowledgeSource = KnowledgeSource.ECS,
) -> GraphNode:
    """Return one node, stating only what a case needs."""
    return GraphNode(
        id=node_id,
        node_type=node_type,
        source=source,
        source_id=canonical_id,
        canonical_id=canonical_id,
        name=name,
        properties={"attackId": attack_id} if attack_id else {},
        provenance=provenance(node_id, source),
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


def chunk(chunk_id: str, source: KnowledgeSource, text: str) -> Chunk:
    """Return one indexable chunk."""
    return Chunk(
        chunk_id=chunk_id,
        parent_record_id=chunk_id.split(":")[0],
        source=source,
        source_id=chunk_id,
        section=SectionType.DETECTION,
        text=text,
    )


SIGMA_CHUNK = chunk(
    "sigma-rule:001",
    KnowledgeSource.SIGMA,
    "Detection Logic:\nselection:\n  Image|endswith: rundll32.exe\n"
    "  CommandLine|contains: -sta\n  EventID: 1\ncondition: selection",
)
ELASTIC_CHUNK = chunk(
    "elastic-rule:001",
    KnowledgeSource.ELASTIC,
    "Query:\nprocess.executable : *rundll32.exe and "
    "process.command_line : *-sta* and event.code : 1",
)


def built_index() -> TextIndex:
    """Return an index holding one chunk of each vocabulary."""
    index = TextIndex(SETTINGS)
    index.build((SIGMA_CHUNK, ELASTIC_CHUNK))
    return index


def lexical(query: RetrievalQuery) -> tuple[Candidate, ...]:
    """Return what the lexical route makes of a query."""
    return LexicalTextRetriever(index=built_index()).retrieve(query, 10)


# ------------------------------------------- 1-3. the named Sigma spellings


def test_image_is_asked_ecs_on_the_graph_and_sigma_on_the_index():
    query = query_of(field("Image"))
    assert query.lexical_fields == ("Image",)
    assert "process.executable" in query.canonical_fields


def test_command_line_is_asked_both_ways():
    query = query_of(field("CommandLine"))
    assert "CommandLine" in query.lexical_fields
    assert "process.command_line" in query.canonical_fields


def test_event_id_is_asked_both_ways():
    query = query_of(field("EventID"))
    assert "EventID" in query.lexical_fields
    assert "event.code" in query.canonical_fields


def test_a_whole_sigma_rule_states_each_field_in_both_vocabularies():
    query = query_of(field("Image"), field("CommandLine"), field("EventID"))
    assert query.lexical_fields == ("Image", "CommandLine", "EventID")
    assert query.canonical_fields == (
        "process.executable",
        "process.command_line",
        "event.code",
    )


# --------------------------------- 4-5. the spelling stays off the graph


def test_a_sigma_spelling_is_not_among_the_identifiers_that_seed():
    """The boundary the whole design rests on.

    ``all_identifiers`` is what the graph seeds from and what ranking compares
    entities against. The rule's own spelling must not be in it.
    """
    query = query_of(field("Image"), field("CommandLine"))
    assert query.all_identifiers == ("process.executable", "process.command_line")
    assert "Image" not in query.all_identifiers
    assert "CommandLine" not in query.all_identifiers


def test_a_sigma_spelling_does_not_reach_the_node_that_shares_its_name():
    """The concrete harm the boundary prevents.

    The corpus holds an ATT&CK data source named ``Image``. It is a real node
    and it is not the process-image field, so a rule writing ``Image`` reaching
    it would be retrieval answering a question nobody asked.
    """
    graph = KnowledgeGraph(
        nodes=(
            node(
                "mitre:enterprise:DS0007",
                canonical_id="enterprise:DS0007",
                name="Image",
                attack_id="DS0007",
                node_type=NodeType.TECHNIQUE,
                source=KnowledgeSource.MITRE,
            ),
            node("ecs:process.executable", canonical_id="process.executable"),
        )
    )
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    _, reports = retriever.retrieve(query_of(field("Image")), 10)
    assert [report.value for report in reports] == ["process.executable"]
    assert [report.node_ids for report in reports] == [("ecs:process.executable",)]


def test_the_canonical_field_is_still_what_the_corpus_documents():
    query = query_of(field("TargetFilename"), field("Image"))
    assert query.canonical_fields == ("file.path", "process.executable")
    assert all(name in ECS_FIELDS for name in query.canonical_fields)


# --------------------------------------------------- 6. Elastic is unchanged


def test_an_ecs_native_field_names_itself_in_both_lists():
    query = query_of(field("process.name"), rule_format=RuleFormat.ELASTIC)
    assert query.lexical_fields == ("process.name",)
    assert query.canonical_fields == ("process.name",)
    assert query.lexical_vocabulary == query.canonical_fields


def test_an_elastic_query_asks_the_index_exactly_what_it_asked_before():
    """The byte-identity check, stated as the string the index receives."""
    query = query_of(
        field("process.name"),
        field("process.command_line"),
        rule_format=RuleFormat.ELASTIC,
        text="process.name : lsass.exe",
    )
    before = RetrievalQuery(
        text=query.text,
        entity_ids=query.entity_ids,
        canonical_fields=query.canonical_fields,
    )
    retriever = LexicalTextRetriever(index=built_index())
    assert retriever._query_text(query) == retriever._query_text(before)


def test_a_caseless_elastic_subfield_is_the_same_string_in_both_lists():
    query = query_of(
        field("process.name", source_field="process.name.caseless"),
        rule_format=RuleFormat.ELASTIC,
    )
    assert query.lexical_fields == ("process.name",)
    assert query.canonical_fields == ("process.name",)


# ------------------------------------------------------- 7. the fallback


def test_a_query_stating_no_lexical_vocabulary_asks_with_the_canonical_one():
    query = RetrievalQuery(canonical_fields=("process.name", "event.code"))
    assert query.lexical_fields == ()
    assert query.lexical_vocabulary == ("process.name", "event.code")


def test_the_fallback_reaches_the_index_too():
    query = RetrievalQuery(canonical_fields=("process.executable",))
    found = lexical(query)
    assert [item.chunk.chunk_id for item in found] == ["elastic-rule:001"]


def test_a_query_stating_neither_asks_with_nothing():
    assert RetrievalQuery(text="a query").lexical_vocabulary == ()


# --------------------------------------------------- 8. no duplicate terms


def test_two_spellings_of_one_field_ask_the_index_once_each_and_the_graph_once():
    """``Image`` and ``ImagePath`` are one ECS field and two written names."""
    query = query_of(field("Image"), field("ImagePath"))
    assert query.canonical_fields == ("process.executable",)
    assert query.lexical_fields == ("Image", "ImagePath")


def test_a_field_named_twice_is_asked_once_in_each_vocabulary():
    query = query_of(field("Image"), field("Image"))
    assert query.canonical_fields == ("process.executable",)
    assert query.lexical_fields == ("Image",)


def test_the_query_text_carries_one_vocabulary_and_not_both():
    query = query_of(field("Image"), field("CommandLine"))
    text = LexicalTextRetriever(index=built_index())._query_text(query)
    assert "process.executable" not in text
    assert "process.command_line" not in text
    assert text.split() == ["Image", "CommandLine"]


def test_a_case_variant_is_scored_once():
    """``_ordered`` keeps both spellings; the index must still count one term."""
    query = RetrievalQuery(lexical_fields=("Image", "image"), canonical_fields=("x",))
    found = lexical(query)
    once = RetrievalQuery(lexical_fields=("Image",), canonical_fields=("x",))
    assert [item.chunk.chunk_id for item in found] == [
        item.chunk.chunk_id for item in lexical(once)
    ]
    assert found[0].evidence[0].raw_score == lexical(once)[0].evidence[0].raw_score


# ------------------------------ 9-10. F1A and F1B, on the route that seeds


def test_f1a_an_ecs_field_seed_is_still_an_exact_identifier():
    graph = KnowledgeGraph(
        nodes=(node("ecs:process.name", canonical_id="process.name"),)
    )
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    found, _ = retriever.retrieve(
        query_of(field("process.name"), rule_format=RuleFormat.ELASTIC), 10
    )
    assert found[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_f1a_a_technique_seed_is_still_an_exact_identifier():
    graph = KnowledgeGraph(
        nodes=(
            node(
                "mitre:enterprise:T1083",
                canonical_id="enterprise:T1083",
                name="File and Directory Discovery",
                attack_id="T1083",
                node_type=NodeType.TECHNIQUE,
                source=KnowledgeSource.MITRE,
            ),
        )
    )
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    found, _ = retriever.retrieve(query_of(reference("T1083")), 10)
    assert found[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


def test_f1a_a_node_reached_by_its_name_is_still_only_a_graph_seed():
    """Unchanged, and now unreachable from a Sigma rule as well.

    A caller may still ask about ``Image`` directly — the query object allows
    it — and when it does, the node found by its name stays a graph seed rather
    than an identity match. What changed is that :func:`rule_query` no longer
    asks that on a rule's behalf.
    """
    graph = KnowledgeGraph(
        nodes=(
            node(
                "mitre:enterprise:DS0007",
                canonical_id="enterprise:DS0007",
                name="Image",
                attack_id="DS0007",
                node_type=NodeType.TECHNIQUE,
                source=KnowledgeSource.MITRE,
            ),
        )
    )
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    found, _ = retriever.retrieve(RetrievalQuery(canonical_fields=("Image",)), 10)
    assert found[0].evidence[0].match_kind is MatchKind.GRAPH_SEED


def test_f1b_graph_evidence_still_keeps_the_seed_beside_the_canonical_id():
    graph = KnowledgeGraph(
        nodes=(
            node(
                "mitre:enterprise:T1083",
                canonical_id="enterprise:T1083",
                name="File and Directory Discovery",
                attack_id="T1083",
                node_type=NodeType.TECHNIQUE,
                source=KnowledgeSource.MITRE,
            ),
        )
    )
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    found, _ = retriever.retrieve(query_of(reference("T1083")), 10)
    assert found[0].evidence[0].matched_entities == ("T1083", "enterprise:T1083")


# ------------------------------------------------------------ 11. C3


def test_c3_an_unresolved_ecs_field_still_reaches_both_lists():
    """``event.action`` is outside the alias table and inside ECS."""
    query = query_of(field("event.action"))
    assert query.canonical_fields == ("event.action",)
    assert query.lexical_fields == ("event.action",)


def test_a_name_outside_the_alias_table_and_outside_ecs_asks_nothing():
    query = query_of(field("auditType.category"))
    assert query.canonical_fields == ()
    assert query.lexical_fields == ()


def test_an_unmapped_field_does_not_become_resolved_through_the_lexical_list():
    query = query_of(field("auditType.category"), field("Image"))
    assert query.lexical_fields == ("Image",)


# -------------------------------------------- 12. the Phase 3F tie-break


def ecs_candidate(name: str) -> Candidate:
    """Return the tied ECS candidate a seeded field produces."""
    from src.graphrag.provenance import RetrievalEvidence

    return Candidate(
        chunk=chunk(f"ecs:{name}", KnowledgeSource.ECS, name),
        evidence=(
            RetrievalEvidence(
                method=RetrievalMethod.GRAPH,
                match_kind=MatchKind.EXACT_IDENTIFIER,
                detail=f"node=ecs:{name} hops=0",
                matched_entities=(name,),
                hops=0,
                raw_score=1.0,
            ),
        ),
    )


def test_the_tie_break_reads_the_canonical_list_and_is_unmoved_by_the_other():
    candidates = [
        ecs_candidate("process.name"),
        ecs_candidate("event.code"),
        ecs_candidate("file.path"),
    ]
    fields = ("file.path", "process.name", "event.code")
    ranker = DeterministicRanker(settings=SETTINGS)
    without = ranker.rank(candidates, RetrievalQuery(canonical_fields=fields))
    with_lexical = ranker.rank(
        candidates,
        RetrievalQuery(
            canonical_fields=fields,
            lexical_fields=("TargetFilename", "Image", "EventID"),
        ),
    )
    assert [item[0].chunk.chunk_id for item in without] == [
        "ecs:file.path",
        "ecs:process.name",
        "ecs:event.code",
    ]
    assert [item[0].chunk.chunk_id for item in with_lexical] == [
        item[0].chunk.chunk_id for item in without
    ]
    assert [item[1].total for item in with_lexical] == [item[1].total for item in without]


def test_a_sigma_rule_still_orders_tied_ecs_candidates_by_its_own_field_order():
    query = query_of(field("EventID"), field("Image"))
    candidates = [ecs_candidate("process.executable"), ecs_candidate("event.code")]
    ranked = DeterministicRanker(settings=SETTINGS).rank(candidates, query)
    assert [item[0].chunk.chunk_id for item in ranked] == [
        "ecs:event.code",
        "ecs:process.executable",
    ]


# ------------------------------------------- 13. the Phase 4B hop budget


def test_the_hop_budget_spends_the_same_way_whatever_the_lexical_list_says():
    nodes = [node("ecs:process.name", canonical_id="process.name")]
    edges = []
    for index in range(6):
        nodes.append(node(f"ecs:near-{index}", canonical_id=f"near-{index}"))
        edges.append(edge("ecs:process.name", f"ecs:near-{index}"))
        nodes.append(node(f"ecs:far-{index}", canonical_id=f"far-{index}"))
        edges.append(edge(f"ecs:near-{index}", f"ecs:far-{index}"))
    graph = KnowledgeGraph(nodes=tuple(nodes), relationships=tuple(edges))
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)

    plain = RetrievalQuery(canonical_fields=("process.name",))
    hybrid = RetrievalQuery(
        canonical_fields=("process.name",), lexical_fields=("Image",)
    )
    found, _ = retriever.retrieve(plain, 9)
    also, _ = retriever.retrieve(hybrid, 9)
    assert [item.chunk.chunk_id for item in found] == [
        item.chunk.chunk_id for item in also
    ]
    assert [item.evidence[0].hops for item in found] == [
        item.evidence[0].hops for item in also
    ]
    assert max(item.evidence[0].hops for item in found) == 2


# ------------------------- 15. which route matches which vocabulary


def test_the_index_finds_the_sigma_record_for_a_sigma_rule():
    found = lexical(query_of(field("Image"), field("CommandLine"), field("EventID")))
    assert [item.chunk.chunk_id for item in found] == ["sigma-rule:001"]


def test_the_same_rule_asked_in_ecs_names_finds_the_elastic_record_instead():
    """The regression this phase repairs, stated as one comparison."""
    query = query_of(field("Image"), field("CommandLine"), field("EventID"))
    before = RetrievalQuery(canonical_fields=query.canonical_fields)
    assert [item.chunk.chunk_id for item in lexical(before)] == ["elastic-rule:001"]
    assert [item.chunk.chunk_id for item in lexical(query)] == ["sigma-rule:001"]


def test_lexical_identity_is_decided_on_the_written_spelling():
    found = lexical(query_of(field("Image"), field("CommandLine")))
    evidence = found[0].evidence[0]
    assert evidence.match_kind is MatchKind.EXACT_IDENTIFIER
    assert evidence.matched_entities == ("image", "commandline")


def test_the_index_is_never_asked_with_a_name_the_graph_was_asked_with():
    query = query_of(field("Image"), field("CommandLine"), field("EventID"))
    text = LexicalTextRetriever(index=built_index())._query_text(query)
    assert not any(name in text for name in query.canonical_fields)


def test_a_technique_identifier_still_reaches_both_routes():
    query = query_of(reference("T1083"), field("Image"))
    assert query.entity_ids == ("T1083",)
    text = LexicalTextRetriever(index=built_index())._query_text(query)
    assert "T1083" in text


# ------------------------------------------------- invariants of the pair


def test_the_two_lists_are_stated_together_or_not_at_all():
    """What lets ``is_empty`` keep reading one of them.

    Both lists come from one filtered stream, so neither can be non-empty while
    the other is empty, whatever the rule named.
    """
    for entities in (
        (field("Image"),),
        (field("auditType.category"),),
        (field("Image"), field("auditType.category")),
        (reference("T1083"),),
        (),
    ):
        query = query_of(*entities)
        assert bool(query.canonical_fields) == bool(query.lexical_fields)


def test_a_rule_naming_no_field_is_still_empty_when_it_names_nothing_else():
    assert query_of().is_empty


def test_asking_twice_asks_the_same_thing():
    entities = (field("Image"), field("CommandLine"), reference("T1083"))
    assert query_of(*entities) == query_of(*entities)
