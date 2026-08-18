"""Which of a rule's own fields survives the result limit.

Every ECS field chunk a query seeds scores the same number. That is not a
coincidence to be tuned away: the seven components are constants of the class.
An ECS record is one chunk and that chunk is always a ``field`` section; an
ECSField node carries no edges, so the candidate is always a hop-0 seed at full
distance; it is seeded by its exact field name, so the identifier and entity
components are both full; and a 175-character definition never reaches the BM25
window, so there is no lexical evidence to separate two of them. Six components
are identical by construction and the seventh is zero.

The sort therefore falls through to chunk id, and a rule naming five fields
against ten result slots has three of its own fields chosen alphabetically. The
fix is an ordering rule, not a scoring one: tied ECS candidates take the order
the rule named them in, and take it *within the positions they already hold*, so
nothing else in the ranking moves.

These tests build candidates directly rather than retrieving them, so each case
states one situation and the scores are whatever the case says they are.
"""

from __future__ import annotations

from src.graphrag.config import GraphRagSettings
from src.graphrag.models import Candidate, Chunk, RetrievalQuery
from src.graphrag.provenance import RetrievalEvidence
from src.graphrag.ranking import DeterministicRanker
from src.graphrag.types import MatchKind, RetrievalMethod, SectionType
from src.knowledge.models.types import KnowledgeSource

RANKER = DeterministicRanker(settings=GraphRagSettings())


def ecs(field: str) -> Candidate:
    """Return the candidate one seeded ECS field produces."""
    return Candidate(
        chunk=Chunk(
            chunk_id=f"ecs:{field}:field:001",
            parent_record_id=f"ecs:{field}",
            source=KnowledgeSource.ECS,
            source_id=field,
            section=SectionType.FIELD,
            text=f"{field}\n\nField: {field}",
        ),
        evidence=(
            RetrievalEvidence(
                method=RetrievalMethod.GRAPH,
                match_kind=MatchKind.EXACT_IDENTIFIER,
                detail=f"node=ecs:ECSField:{field} hops=0",
                matched_entities=(field,),
                hops=0,
                raw_score=1.0,
            ),
        ),
    )


def rule(chunk_id: str, *, technique: str = "T1059") -> Candidate:
    """Return a rule candidate reached through a technique, not through a field."""
    return Candidate(
        chunk=Chunk(
            chunk_id=chunk_id,
            parent_record_id=chunk_id.rsplit(":", 2)[0],
            source=KnowledgeSource.ELASTIC,
            source_id=chunk_id,
            section=SectionType.SUMMARY,
            text="a rule",
        ),
        evidence=(
            RetrievalEvidence(
                method=RetrievalMethod.GRAPH,
                match_kind=MatchKind.EXACT_IDENTIFIER,
                detail="hops=0",
                matched_entities=(technique,),
                hops=0,
                raw_score=1.0,
            ),
        ),
    )


def query(*fields: str, entities: tuple[str, ...] = ()) -> RetrievalQuery:
    """Return a query naming fields in the order given."""
    return RetrievalQuery(text="", entity_ids=entities, canonical_fields=fields)


def order(ranked: tuple[tuple[Candidate, object], ...]) -> list[str]:
    """Return the chunk ids of a ranking, in rank order."""
    return [item[0].chunk.chunk_id for item in ranked]


# ------------------------------------------------- 1. field order decides the tie


def test_tied_ecs_candidates_follow_the_order_the_query_named_them():
    """The rule's field order, not the alphabet, decides which field leads."""
    asked = query("process.name", "file.path", "event.action")
    # Supplied in the reverse of the asked order, and alphabetically ordered
    # against it, so neither input order nor chunk id can produce the answer.
    ranked = RANKER.rank([ecs("event.action"), ecs("file.path"), ecs("process.name")], asked)

    assert order(ranked) == [
        "ecs:process.name:field:001",
        "ecs:file.path:field:001",
        "ecs:event.action:field:001",
    ]


def test_the_tied_candidates_really_do_share_one_score():
    """The premise of the whole pass: without a tie there is nothing to decide."""
    asked = query("process.name", "file.path")
    ranked = RANKER.rank([ecs("file.path"), ecs("process.name")], asked)

    totals = {item[1].total for item in ranked}
    assert len(totals) == 1


def test_a_rule_keeps_its_first_named_fields_when_the_limit_cuts_the_run():
    """The case this exists for: the survivors are the fields named first."""
    asked = query("process.name", "process.args", "user.name", "file.path")
    ranked = RANKER.rank(
        [ecs("file.path"), ecs("process.args"), ecs("user.name"), ecs("process.name")],
        asked,
    )

    assert order(ranked)[:2] == ["ecs:process.name:field:001", "ecs:process.args:field:001"]


# ------------------------------------------------------- 2. nothing else moves


def tied_non_ecs(chunk_id: str, source: KnowledgeSource, field: str) -> Candidate:
    """Return a non-ECS candidate scoring exactly what a seeded ECS field scores.

    Sigma and MITRE carry a source weight of 1.00, the same value ECS is raised
    to when the query names a field, so a ``field`` section reached as a hop-0
    exact match lands on the identical total. It is the only way another source
    reaches the ECS plateau, and it is what makes a genuine cross-source tie
    testable at all.
    """
    return Candidate(
        chunk=Chunk(
            chunk_id=chunk_id,
            parent_record_id=chunk_id.rsplit(":", 2)[0],
            source=source,
            source_id=chunk_id,
            section=SectionType.FIELD,
            text="not an ECS definition",
        ),
        evidence=ecs(field).evidence,
    )


def test_a_non_ecs_candidate_keeps_the_rank_the_score_gave_it():
    """Other sources are not reordered, and not stepped over.

    Every ECS chunk id begins ``ecs:``, which sorts before ``elastic:``,
    ``lolbas:``, ``mitre:`` and ``sigma:``, so within one tied run the ECS
    members are always the leading block. The reordering happens inside that
    block and the tied Sigma candidate keeps the rank its score earned.
    """
    asked = query("process.name", "file.path")
    tied = tied_non_ecs("sigma:aaa:field:0", KnowledgeSource.SIGMA, "file.path")
    ranked = RANKER.rank([ecs("file.path"), tied, ecs("process.name")], asked)

    assert {item[1].total for item in ranked} == {0.8455}
    assert order(ranked) == [
        "ecs:process.name:field:001",
        "ecs:file.path:field:001",
        "sigma:aaa:field:0",
    ]


def test_reversing_the_field_order_never_moves_a_non_ecs_candidate():
    """The interleaving between sources is exactly what the score produced."""
    supplied = [
        ecs("file.path"),
        tied_non_ecs("mitre:aaa:field:0", KnowledgeSource.MITRE, "process.name"),
        ecs("process.name"),
    ]

    def sources(*fields: str) -> list[KnowledgeSource]:
        return [item[0].chunk.source for item in RANKER.rank(supplied, query(*fields))]

    forwards = sources("process.name", "file.path")
    backwards = sources("file.path", "process.name")

    assert forwards == backwards


def test_a_query_naming_no_field_is_left_exactly_as_it_was():
    """No field order to apply, and nothing pretending there is one."""
    supplied = [rule("elastic:ccc:summary:0"), rule("elastic:aaa:summary:0")]
    ranked = RANKER.rank(supplied, query(entities=("T1059",)))

    assert order(ranked) == ["elastic:aaa:summary:0", "elastic:ccc:summary:0"]


# --------------------------------------------------------- 3. score still wins


def test_a_higher_score_outranks_an_earlier_field():
    """Field position orders a tie; it never overturns one."""
    asked = query("process.name", "file.path")
    lifted = Candidate(
        chunk=ecs("file.path").chunk,
        evidence=(
            *ecs("file.path").evidence,
            RetrievalEvidence(
                method=RetrievalMethod.TEXT,
                match_kind=MatchKind.LEXICAL,
                detail="bm25=9.0",
                raw_score=9.0,
            ),
        ),
    )
    ranked = RANKER.rank([ecs("process.name"), lifted], asked)

    assert ranked[0][1].total > ranked[1][1].total
    assert order(ranked)[0] == "ecs:file.path:field:001"


def test_an_ecs_candidate_the_query_did_not_name_sorts_after_the_ones_it_did():
    """An unnamed field does not jump the queue, and keeps its chunk id order."""
    asked = query("process.name")
    ranked = RANKER.rank([ecs("agent.id"), ecs("zzz.field"), ecs("process.name")], asked)

    assert order(ranked) == [
        "ecs:process.name:field:001",
        "ecs:agent.id:field:001",
        "ecs:zzz.field:field:001",
    ]


# ------------------------------------------------------------ 4. determinism


def test_the_ranking_is_identical_across_runs():
    """A total order, still, and one that does not depend on input order."""
    asked = query("process.name", "file.path", "event.action")
    supplied = [
        ecs("event.action"),
        ecs("process.name"),
        rule("elastic:aaa:summary:0"),
        ecs("file.path"),
    ]

    first = order(RANKER.rank(supplied, asked))
    second = order(RANKER.rank(list(reversed(supplied)), asked))

    assert first == second


def test_two_candidates_naming_no_field_keep_chunk_id_order():
    """The existing fallback is intact wherever field order says nothing."""
    asked = query("process.name")
    ranked = RANKER.rank([rule("elastic:zzz:summary:0"), rule("elastic:aaa:summary:0")], asked)

    assert order(ranked) == ["elastic:aaa:summary:0", "elastic:zzz:summary:0"]


# ------------------------------------- 5. the measured case this phase resolves


def test_the_suspicious_file_changes_rule_keeps_the_field_it_named_first():
    """The one rule in the 187-rule population that lost a field to spelling.

    ``Suspicious File Changes Activity Detected`` names ``process.executable``,
    ``file.path`` and ``process.name``, and had room for two. Chunk id order kept
    ``file.path`` and ``process.executable`` and dropped ``process.name``, which
    is the field the rule names first.
    """
    asked = query("process.executable", "file.path", "process.name")
    ranked = RANKER.rank(
        [ecs("file.path"), ecs("process.executable"), ecs("process.name")], asked
    )

    assert order(ranked)[:2] == [
        "ecs:process.executable:field:001",
        "ecs:file.path:field:001",
    ]


# -------------------------------------------------------- 6. weights unchanged


def test_the_ranking_weights_are_the_documented_ones():
    """No component was added, removed or reweighted to achieve any of this."""
    weights = GraphRagSettings().weights

    assert (weights.exact_identifier, weights.entity_match, weights.graph) == (0.30, 0.20, 0.20)
    assert (weights.lexical, weights.source) == (0.15, 0.07)
    assert (weights.distance, weights.section) == (0.05, 0.03)
    assert weights.total == 1.0


def test_an_ecs_candidate_scores_what_it_scored_before():
    """The plateau is untouched: ordering changed, arithmetic did not."""
    asked = query("process.name")
    ranked = RANKER.rank([ecs("process.name")], asked)

    assert ranked[0][1].total == 0.8455


# ------------------------------------------------- 7. other sources unaffected


def test_sigma_and_mitre_candidates_are_never_reordered_by_field_position():
    """Only ECS is permuted, whatever a candidate's evidence happens to name."""
    asked = query("process.name", "file.path")
    sigma = Candidate(
        chunk=Chunk(
            chunk_id="sigma:zzz:summary:0",
            parent_record_id="sigma:zzz",
            source=KnowledgeSource.SIGMA,
            source_id="zzz",
            section=SectionType.FIELD,
            text="a sigma rule",
        ),
        # Names the query's *second* field. If the pass were source-blind this
        # would move; it must not.
        evidence=ecs("file.path").evidence,
    )
    mitre = Candidate(
        chunk=Chunk(
            chunk_id="mitre:aaa:field:0",
            parent_record_id="mitre:aaa",
            source=KnowledgeSource.MITRE,
            source_id="aaa",
            section=SectionType.FIELD,
            text="a technique",
        ),
        evidence=ecs("process.name").evidence,
    )
    ranked = RANKER.rank([sigma, mitre], asked)

    assert order(ranked) == ["mitre:aaa:field:0", "sigma:zzz:summary:0"]
