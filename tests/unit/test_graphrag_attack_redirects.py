"""Following ATT&CK's own renumbering, without rewriting the rule.

The corpus is a current ATT&CK snapshot and the rules citing it are not, so a
maintained Elastic rule names ``T1562.001`` and no node carries that identifier.
ATT&CK revoked it in favour of ``T1685``, which the corpus does hold. Seeding the
walk at ``T1685`` recovers evidence that would otherwise be lost; claiming the
rule *said* ``T1685`` would be a different and false statement.

Everything below is about keeping those two apart. The seed reports both
identifiers and a status of its own — ``redirected``, neither ``resolved`` nor
``unresolved`` — the rule's own vocabulary never changes, no node is invented in
any branch, and a redirect ATT&CK has not authorised, or one that would require
choosing between successors, is refused rather than guessed.

The graph cases build small graphs rather than the corpus so each states one
situation. The last group asks the real corpus, because the thirteen authorised
mappings are a claim about *this* knowledge base and only it can answer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.graph.graph_builder import GraphBuilder
from src.graph.models import GraphNode, KnowledgeGraph
from src.graph.provenance import NodeProvenance
from src.graph.types import NodeType
from src.graphrag.attack_redirects import (
    ATTACK_REDIRECTS,
    AttackRedirect,
    redirect_for,
)
from src.graphrag.config import GraphRagSettings
from src.graphrag.graph_retriever import KnowledgeGraphRetriever
from src.graphrag.models import Chunk, RetrievalQuery
from src.graphrag.provenance import redirect_groups
from src.graphrag.retriever import GraphRagRetriever
from src.graphrag.types import MatchKind, SectionType, SeedStatus
from src.knowledge.models.types import KnowledgeSource
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository

SETTINGS = GraphRagSettings()

AUTHORISED = {
    "T1070.001": "T1685.005",
    "T1070.002": "T1685.006",
    "T1086": "T1059.001",
    "T1547.011": "T1647",
    "T1562": "T1685",
    "T1562.001": "T1685",
    "T1562.002": "T1685.001",
    "T1562.004": "T1686",
    "T1562.006": "T1685",
    "T1562.007": "T1686.001",
    "T1562.008": "T1685.002",
    "T1562.010": "T1689",
    "T1656": "T1684.001",
}
"""The thirteen mappings this phase authorised, restated independently.

Deliberately a second copy rather than an import of the table under test: a test
that reads its expectation out of the thing it is checking cannot detect an
entry being changed, added or dropped, which is exactly the change that matters
most here.
"""


# ------------------------------------------------------------------ helpers


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
                source=KnowledgeSource.MITRE,
                source_id=parent_record_id,
                section=SectionType.SUMMARY,
                text=parent_record_id,
            ),
        )


def technique(attack_id: str, *, name: str = "") -> GraphNode:
    """Return one ATT&CK technique node carrying an identifier."""
    node_id = f"mitre:Technique:enterprise:{attack_id}"
    return GraphNode(
        id=node_id,
        node_type=NodeType.TECHNIQUE,
        source=KnowledgeSource.MITRE,
        source_id=f"enterprise:{attack_id}",
        canonical_id=f"enterprise:{attack_id}",
        name=name or attack_id,
        properties={"attackId": attack_id},
        provenance=NodeProvenance(
            source=KnowledgeSource.MITRE,
            source_id=f"enterprise:{attack_id}",
            record_id=node_id,
            dataset="probe.jsonl",
            line_number=1,
        ),
    )


def seed(nodes, identifiers):
    """Return the candidates and seed reports one query produces."""
    graph = KnowledgeGraph(nodes=tuple(nodes), relationships=())
    retriever = KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS)
    return retriever.retrieve(
        RetrievalQuery(entity_ids=tuple(identifiers), max_results=10), 50
    )


def one_report(nodes, identifier):
    """Return the single seed report a one-identifier query produces."""
    _, reports = seed(nodes, [identifier])
    assert len(reports) == 1
    return reports[0]


# ---------------------------------------------------------------- the table


def test_the_table_holds_exactly_the_thirteen_authorised_mappings():
    assert {key: value[0] for key, value in ATTACK_REDIRECTS.items()} == AUTHORISED


def test_every_authorised_mapping_is_one_to_one():
    for original in AUTHORISED:
        found = redirect_for(original)
        assert found is not None
        assert found.is_one_to_one
        assert found.successor == AUTHORISED[original]


def test_the_redirect_preserves_the_identifier_it_was_asked_about():
    found = redirect_for("T1562.001")
    assert found is not None
    assert found.original_id == "T1562.001"


def test_lookup_is_case_and_whitespace_insensitive():
    found = redirect_for("  t1562.001  ")
    assert found is not None
    assert found.successor == "T1685"


def test_a_current_identifier_has_no_redirect():
    assert redirect_for("T1059.001") is None
    assert redirect_for("T1685") is None


def test_a_malformed_identifier_has_no_redirect():
    for value in ("", "   ", "NOTANID", "T156", "T15621", "T1562.1", "TA0112", "t1562-001"):
        assert redirect_for(value) is None


def test_no_tactic_identifier_is_redirected():
    """TA0112 is not added in this phase, and no redirect may stand in for it."""
    assert redirect_for("TA0112") is None
    assert not any(key.startswith("TA") for key in ATTACK_REDIRECTS)


def test_no_mapping_points_at_a_deprecated_identifier():
    """A successor that is itself revoked would be a chain, and there are none."""
    for successors in ATTACK_REDIRECTS.values():
        for successor in successors:
            assert successor not in ATTACK_REDIRECTS


# ------------------------------------------------------- one-to-many safety


def test_a_one_to_many_redirect_refuses_to_name_a_single_successor():
    many = AttackRedirect(original_id="T0001", successors=("T0002", "T0003"))
    assert not many.is_one_to_one
    with pytest.raises(ValueError, match="no single successor"):
        _ = many.successor


def test_a_one_to_many_redirect_is_reported_ambiguous_and_seeds_nothing(monkeypatch):
    """A future many-successor entry must not be collapsed to its first member."""
    monkeypatch.setattr(
        "src.graphrag.attack_redirects.ATTACK_REDIRECTS",
        {"T1562": ("T1685", "T1686")},
    )
    nodes = [technique("T1685"), technique("T1686")]
    candidates, reports = seed(nodes, ["T1562"])

    assert reports[0].status == SeedStatus.AMBIGUOUS.value
    assert reports[0].resolved_value is None
    assert set(reports[0].node_ids) == {
        "mitre:Technique:enterprise:T1685",
        "mitre:Technique:enterprise:T1686",
    }
    assert "none chosen" in reports[0].note
    assert candidates == ()


def test_a_one_to_many_redirect_lists_every_candidate_it_declined_to_choose(monkeypatch):
    monkeypatch.setattr(
        "src.graphrag.attack_redirects.ATTACK_REDIRECTS",
        {"T1562": ("T1685", "T1686")},
    )
    report = one_report([technique("T1685"), technique("T1686")], "T1562")
    assert "T1685" in report.note
    assert "T1686" in report.note


# ------------------------------------------------------------- seed reports


def test_a_redirected_seed_reports_the_redirected_status():
    report = one_report([technique("T1685")], "T1562.001")
    assert report.status == SeedStatus.REDIRECTED.value
    assert report.status != SeedStatus.RESOLVED.value


def test_a_redirected_seed_preserves_the_original_identifier():
    report = one_report([technique("T1685")], "T1562.001")
    assert report.value == "T1562.001"


def test_a_redirected_seed_states_the_successor_separately():
    report = one_report([technique("T1685")], "T1562.001")
    assert report.resolved_value == "T1685"


def test_a_redirected_seed_names_the_node_it_reached():
    report = one_report([technique("T1685")], "T1562.001")
    assert report.node_ids == ("mitre:Technique:enterprise:T1685",)


def test_a_redirected_seed_says_why_in_its_note():
    report = one_report([technique("T1685")], "T1562.001")
    assert "revoked" in report.note
    assert "T1685" in report.note


def test_a_resolved_seed_names_no_successor():
    """Only a redirect sets it, so the two cannot be confused by a reader."""
    report = one_report([technique("T1685")], "T1685")
    assert report.status == SeedStatus.RESOLVED.value
    assert report.resolved_value is None


def test_the_rendered_report_shows_both_identifiers():
    report = one_report([technique("T1685")], "T1562.001")
    assert "T1562.001" in str(report)
    assert "T1685" in str(report)
    assert "redirected" in str(report)


# --------------------------------------------------------- no node invented


def test_a_redirect_whose_successor_the_corpus_lacks_stays_unresolved():
    report = one_report([technique("T9999")], "T1562.001")
    assert report.status == SeedStatus.UNRESOLVED.value
    assert report.resolved_value is None
    assert report.node_ids == ()


def test_a_redirect_whose_successor_is_missing_says_so():
    report = one_report([technique("T9999")], "T1562.001")
    assert "T1685" in report.note


def test_a_redirect_whose_successor_is_ambiguous_chooses_nothing():
    duplicate = GraphNode(
        id="mitre:Technique:mobile:T1685",
        node_type=NodeType.TECHNIQUE,
        source=KnowledgeSource.MITRE,
        source_id="mobile:T1685",
        canonical_id="mobile:T1685",
        name="T1685",
        properties={"attackId": "T1685"},
        provenance=NodeProvenance(
            source=KnowledgeSource.MITRE,
            source_id="mobile:T1685",
            record_id="mitre:Technique:mobile:T1685",
            dataset="probe.jsonl",
            line_number=2,
        ),
    )
    candidates, reports = seed([technique("T1685"), duplicate], ["T1562.001"])
    assert reports[0].status == SeedStatus.AMBIGUOUS.value
    assert len(reports[0].node_ids) == 2
    assert candidates == ()


def test_an_unmapped_missing_identifier_is_unchanged():
    report = one_report([technique("T1685")], "T9998")
    assert report.status == SeedStatus.UNRESOLVED.value
    assert report.note == "no node carries this identifier"


def test_a_malformed_identifier_stays_unresolved():
    for value in ("NOTANID", "T156", "T1562.1"):
        assert one_report([technique("T1685")], value).status == SeedStatus.UNRESOLVED.value


# ------------------------------------------------------------ graph seeding


def test_the_walk_starts_at_the_successor_node():
    candidates, _ = seed([technique("T1685")], ["T1562.001"])
    assert [item.chunk.parent_record_id for item in candidates] == [
        "mitre:Technique:enterprise:T1685"
    ]


def test_a_redirected_seed_claims_no_exact_identifier_match():
    """The node does not carry ``T1562.001``, so no evidence may say it does."""
    candidates, _ = seed([technique("T1685")], ["T1562.001"])
    evidence = candidates[0].evidence[0]
    assert evidence.match_kind is MatchKind.GRAPH_SEED
    assert evidence.match_kind is not MatchKind.EXACT_IDENTIFIER
    assert "T1562.001" not in evidence.matched_entities


def test_a_direct_hit_still_claims_an_exact_identifier_match():
    candidates, _ = seed([technique("T1685")], ["T1685"])
    assert candidates[0].evidence[0].match_kind is MatchKind.EXACT_IDENTIFIER


# ------------------------------------------------------------ collapse/arity


def test_three_deprecated_identifiers_collapsing_to_one_node_keep_three_reports():
    _, reports = seed([technique("T1685")], ["T1562", "T1562.001", "T1562.006"])
    assert [report.value for report in reports] == ["T1562", "T1562.001", "T1562.006"]
    assert all(report.status == SeedStatus.REDIRECTED.value for report in reports)
    assert all(report.resolved_value == "T1685" for report in reports)


def test_the_collapse_seeds_the_node_once():
    candidates, _ = seed([technique("T1685")], ["T1562", "T1562.001", "T1562.006"])
    assert len(candidates) == 1


def test_redirect_groups_names_the_successor_and_every_original():
    _, reports = seed([technique("T1685")], ["T1562", "T1562.001", "T1562.006"])
    assert redirect_groups(reports) == (("T1685", ("T1562", "T1562.001", "T1562.006")),)


def test_redirect_groups_distinguishes_a_collapse_from_a_direct_reference():
    _, collapsed = seed([technique("T1685")], ["T1562", "T1562.001"])
    _, direct = seed([technique("T1685")], ["T1685"])
    assert redirect_groups(collapsed) == (("T1685", ("T1562", "T1562.001")),)
    assert redirect_groups(direct) == ()


def test_redirect_groups_orders_successors_and_keeps_originals_in_query_order():
    nodes = [technique("T1685"), technique("T1686")]
    _, reports = seed(nodes, ["T1562.004", "T1562.006", "T1562", "T1562.001"])
    assert redirect_groups(reports) == (
        ("T1685", ("T1562.006", "T1562", "T1562.001")),
        ("T1686", ("T1562.004",)),
    )


def test_a_repeated_identifier_is_reported_once_per_occurrence_and_seeded_once():
    candidates, reports = seed([technique("T1685")], ["T1562.001", "T1562.001"])
    assert len(reports) == 2
    assert len(candidates) == 1
    assert redirect_groups(reports) == (("T1685", ("T1562.001",)),)


def test_seeding_is_deterministic_across_runs():
    nodes = [technique("T1685"), technique("T1686")]
    first = seed(nodes, ["T1562", "T1562.004", "T1562.001"])
    second = seed(nodes, ["T1562", "T1562.004", "T1562.001"])
    assert [item.chunk.chunk_id for item in first[0]] == [
        item.chunk.chunk_id for item in second[0]
    ]
    assert first[1] == second[1]


# -------------------------------------------------------- lexical isolation


def test_the_query_object_is_never_rewritten():
    query = RetrievalQuery(
        entity_ids=("T1562.001",),
        canonical_fields=("process.name",),
        lexical_fields=("Image",),
        max_results=10,
    )
    graph = KnowledgeGraph(nodes=(technique("T1685"),), relationships=())
    KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS).retrieve(query, 50)

    assert query.entity_ids == ("T1562.001",)
    assert query.canonical_fields == ("process.name",)
    assert query.lexical_fields == ("Image",)
    assert query.all_identifiers == ("T1562.001", "process.name")
    assert query.lexical_vocabulary == ("Image",)


def test_no_successor_reaches_the_lexical_vocabulary():
    query = RetrievalQuery(entity_ids=("T1562.001",), lexical_fields=("Image",))
    graph = KnowledgeGraph(nodes=(technique("T1685"),), relationships=())
    KnowledgeGraphRetriever(graph, OneChunkPerRecord(), SETTINGS).retrieve(query, 50)

    asked = (*query.entity_ids, *query.lexical_vocabulary)
    assert "T1685" not in asked
    assert all("T1685" not in item for item in asked)


# ----------------------------------------------------- against the real corpus


@pytest.fixture(scope="module")
def corpus_retriever():
    """Return a retriever built over the repository's own knowledge base."""
    root = Path(__file__).resolve().parents[2] / "resources" / "knowledge"
    repository = JsonlKnowledgeRepository.from_root(root)
    retriever = GraphRagRetriever(repository, GraphBuilder.over(repository).build(), SETTINGS)
    retriever.build_index()
    return retriever


@pytest.mark.parametrize(("original", "successor"), sorted(AUTHORISED.items()))
def test_each_authorised_mapping_resolves_against_the_real_corpus(
    corpus_retriever, original, successor
):
    result = corpus_retriever.retrieve(RetrievalQuery(text="probe", entity_ids=(original,)))
    report = result.seeds[0]
    assert report.value == original
    assert report.status == SeedStatus.REDIRECTED.value
    assert report.resolved_value == successor
    assert report.node_ids == (f"mitre:Technique:enterprise:{successor}",)


def test_the_corpus_reports_redirected_seeds_apart_from_resolved_and_unresolved(
    corpus_retriever,
):
    result = corpus_retriever.retrieve(
        RetrievalQuery(text="probe", entity_ids=("T1562.001", "T1059.001", "T9999"))
    )
    assert [item.value for item in result.redirected_seeds] == ["T1562.001"]
    assert [item.value for item in result.unresolved_seeds] == ["T9999"]
    assert "T1562.001" not in {item.value for item in result.unresolved_seeds}


def test_the_corpus_still_holds_no_node_for_a_deprecated_identifier(corpus_retriever):
    """The redirect is a lookup, never a record. Nothing was added to the corpus."""
    result = corpus_retriever.retrieve(RetrievalQuery(text="probe", entity_ids=("T1562",)))
    node_id = result.seeds[0].node_ids[0]
    assert "T1562" not in node_id
    assert node_id == "mitre:Technique:enterprise:T1685"


def test_ta0112_resolves_to_the_real_tactic_and_not_through_a_redirect(corpus_retriever):
    """TA0112 is a record now, and it must be reached as one.

    Until the corpus carried the Defense Impairment tactic this asserted the
    opposite — that ``TA0112`` reached nothing — because the point was that the
    redirect layer had not invented a tactic to fill the gap. The corpus now
    holds the authoritative record, so the negative invariant is obsolete; what
    replaces it is the same guarantee stated positively. ``TA0112`` resolves the
    ordinary way, to the ordinary node, and the redirect table is still not
    involved in how it got there.
    """
    result = corpus_retriever.retrieve(RetrievalQuery(text="probe", entity_ids=("TA0112",)))
    report = result.seeds[0]

    assert report.status == SeedStatus.RESOLVED.value
    assert report.status != SeedStatus.REDIRECTED.value
    assert report.node_ids == ("mitre:Tactic:enterprise:TA0112",)

    # Resolved, so nothing stood in for it: a successor is a redirect's field alone.
    assert report.resolved_value is None
    assert result.redirected_seeds == ()

    # And the table still says nothing about it, in either direction.
    assert redirect_for("TA0112") is None
    assert "TA0112" not in ATTACK_REDIRECTS
    assert "TA0112" not in {s for v in ATTACK_REDIRECTS.values() for s in v}


def test_the_real_corpus_collapse_keeps_all_three_originals(corpus_retriever):
    result = corpus_retriever.retrieve(
        RetrievalQuery(text="probe", entity_ids=("T1562", "T1562.001", "T1562.006"))
    )
    assert result.redirect_groups == (("T1685", ("T1562", "T1562.001", "T1562.006")),)
