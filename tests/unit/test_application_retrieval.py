"""Stage-18 retrieval seeding.

What a rule asks the corpus is decided here and nowhere else, so it is checked
here against the real Stage-08, Stage-09 and Stage-10 output for a real rule
rather than against a hand-written mapping.

The seeding functions are pure and take no retriever, which is why none of these
tests reads a dataset, builds a graph or indexes anything. Assembly is exercised
by the integration test instead.
"""

from __future__ import annotations

import dataclasses

from src.application.pipeline import parsed_rule_from_query
from src.application.requests import EngineRequest
from src.application.retrieval import (
    CORPUS_KEYED_TYPES,
    DEFAULT_SETTINGS,
    RetrievalService,
    requirement_query,
    rule_query,
)
from src.context.context_builder import ContextBuilder, rule_context_from_parsed
from src.core.types import ReasoningOperation
from src.entities.extractor import EntityExtractor
from src.graphrag.config import GraphRagSettings
from src.graphrag.models import RetrievalQuery, RetrievalResult
from src.graphrag.types import RetrievalMode
from src.mapping.entity_mapper import EntityMapper
from src.parser.parser import RuleParser
from tests.fixtures import stage15 as fixtures

REQUIREMENT = "Detect encoded PowerShell command execution on Windows endpoints."
RAW_QUERY = 'process.name:"powershell.exe" and process.command_line:*-enc*'

REFERENCING_RULE = """title: Referencing rule
id: 1f0c9d5e-0000-4c11-9f00-2b7a5c9e0001
status: experimental
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.name: powershell.exe
    DestinationIp: 10.0.0.0/8
    EventID: 4688
    Hashes: 6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c
  condition: selection
tags:
  - attack.t1059.001
  - attack.g0010
  - attack.s0039
  - CVE-2021-44228
"""
"""One rule stating every kind of value that can carry a canonical identifier.

Written as a Sigma document and put through the real parser, extractor and
mapper, so the mapping statuses under test are the ones Stage-10 actually
produces rather than ones assembled by hand. It states, in one place: an ATT&CK
technique, a group, a software, a CVE, a private network, an event identifier
and a hash digest.
"""


def mapped():
    """Return the real mapped entities of the fixture rule."""
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    return rule_context_from_parsed(parsed), EntityMapper().map(
        EntityExtractor().extract(parsed)
    )


def mapped_text(text: str):
    """Return the real rule context and mapped entities of one rule document."""
    parsed = RuleParser().parse(text)
    return rule_context_from_parsed(parsed), EntityMapper().map(
        EntityExtractor().extract(parsed)
    )


def seeds_of(text: str):
    """Return what one rule document asks the corpus."""
    rule, mappings = mapped_text(text)
    return rule_query(rule, mappings, top_k=10)


class RecordingRetriever:
    """A retriever that answers with one result and keeps every query."""

    def __init__(self, result: RetrievalResult) -> None:
        self.result = result
        self.queries: list[RetrievalQuery] = []

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        self.queries.append(query)
        return self.result


def test_a_rule_asks_with_the_identifiers_the_corpus_is_keyed_by():
    """Resolved is not the same question as keyable.

    A severity resolves — it is a real member of a closed vocabulary — and no
    record in the corpus answers to it. The seed list states what the corpus can
    be asked about, which is a smaller thing.
    """
    query = seeds_of(REFERENCING_RULE)
    rule, mappings = mapped_text(REFERENCING_RULE)
    expected = [
        item.canonical_id
        for item in mappings.resolved
        if item.canonical_id and item.canonical_type in CORPUS_KEYED_TYPES
    ]
    assert list(query.entity_ids) == list(dict.fromkeys(expected))
    assert query.entity_ids


def test_a_rule_asks_with_its_resolved_ecs_fields():
    rule, mappings = mapped()
    query = rule_query(rule, mappings, top_k=10)
    expected = [item.canonical_field for item in mappings.resolved if item.canonical_field]
    assert list(query.canonical_fields) == list(dict.fromkeys(expected))
    assert query.canonical_fields


def test_nothing_unresolved_is_ever_asked_with():
    rule, mappings = mapped()
    query = rule_query(rule, mappings, top_k=10)
    for item in mappings.unresolved:
        assert item.canonical_id not in query.entity_ids or item.canonical_id is None


def test_repeated_identifiers_are_asked_once_in_first_seen_order():
    rule, mappings = mapped_text(REFERENCING_RULE)
    keyed = next(
        item for item in mappings.resolved if item.canonical_type in CORPUS_KEYED_TYPES
    )
    duplicated = dataclasses.replace(
        mappings,
        entities=(keyed, *mappings.entities, dataclasses.replace(keyed, canonical_id="T9999")),
    )
    query = rule_query(rule, duplicated, top_k=10)
    assert len(query.entity_ids) == len(set(query.entity_ids))
    assert query.entity_ids[-1] == "T9999"


def test_a_blank_identifier_is_never_asked_with():
    rule, mappings = mapped()
    blanked = dataclasses.replace(
        mappings,
        entities=tuple(
            dataclasses.replace(item, canonical_id=None) for item in mappings.entities
        ),
    )
    assert rule_query(rule, blanked, top_k=10).entity_ids == ()


def test_a_rule_asks_with_its_query_text():
    rule, mappings = mapped()
    assert rule_query(rule, mappings, top_k=10).text == rule.query


def test_a_format_stating_no_query_expression_asks_on_identifiers_alone():
    """Sigma keeps its detection in named blocks; no query is invented from them."""
    rule, mappings = mapped_text(REFERENCING_RULE)
    without = dataclasses.replace(rule, query="")
    query = rule_query(without, mappings, top_k=10)
    assert query.text == ""
    assert not query.is_empty
    assert query.entity_ids


# --------------------------------------------------------- seed keyability (F2)


def test_an_attack_technique_is_asked_with():
    assert "T1059.001" in seeds_of(REFERENCING_RULE).entity_ids


def test_an_attack_group_and_software_are_asked_with():
    entity_ids = seeds_of(REFERENCING_RULE).entity_ids
    assert "G0010" in entity_ids
    assert "S0039" in entity_ids


def test_a_cve_is_asked_with():
    assert "CVE-2021-44228" in seeds_of(REFERENCING_RULE).entity_ids


def test_a_network_address_is_never_asked_with():
    entity_ids = seeds_of(REFERENCING_RULE).entity_ids
    assert not any(value.startswith("10.0.0.0") for value in entity_ids)


def test_a_severity_is_never_asked_with():
    assert "medium" not in seeds_of(REFERENCING_RULE).entity_ids


def test_a_rule_status_is_never_asked_with():
    assert "experimental" not in seeds_of(REFERENCING_RULE).entity_ids


def test_an_event_identifier_is_never_asked_with():
    assert "4688" not in seeds_of(REFERENCING_RULE).entity_ids


def test_a_file_hash_is_never_asked_with():
    entity_ids = seeds_of(REFERENCING_RULE).entity_ids
    assert not any(len(value) == 40 and value.isalnum() for value in entity_ids)


def test_every_seed_names_a_kind_of_thing_the_corpus_holds():
    _, mappings = mapped_text(REFERENCING_RULE)
    keyed = {
        item.canonical_id
        for item in mappings.resolved
        if item.canonical_type in CORPUS_KEYED_TYPES and item.canonical_id
    }
    assert set(seeds_of(REFERENCING_RULE).entity_ids) == keyed


def test_the_fixture_rule_names_no_corpus_identifier_at_all():
    """The Stage-15 fixture states no ATT&CK tag, so it has nothing to ask with.

    Its severity and status still resolve, and still reach the context. They are
    simply not questions the corpus can answer.
    """
    rule, mappings = mapped()
    assert rule_query(rule, mappings, top_k=10).entity_ids == ()
    assert {item.canonical_id for item in mappings.resolved if item.canonical_id} == {
        "medium",
        "experimental",
    }


def test_filtering_a_seed_does_not_remove_the_entity_or_its_value():
    """The value is still extracted, still mapped, and still reaches the package."""
    parsed = RuleParser().parse(REFERENCING_RULE)
    entities = EntityExtractor().extract(parsed)
    mappings = EntityMapper().map(entities)
    package = ContextBuilder().build(
        ReasoningOperation.ANALYZE.context_operation,
        rule=rule_context_from_parsed(parsed),
        entities=entities,
        mappings=mappings,
    )
    rendered = "\n".join(item.text for item in package.items)
    for value in ("10.0.0.0/8", "4688", "medium", "experimental"):
        assert value in rendered, f"{value!r} was dropped from the context"


def test_seeding_is_deterministic():
    assert seeds_of(REFERENCING_RULE) == seeds_of(REFERENCING_RULE)


def test_the_field_seeds_are_untouched_by_keyability():
    """Field seeds travel on canonical_field and are not narrowed.

    Every value the field mapper sets is a field name, so the list needs no
    filtering. It still states the vendor spellings a Sigma rule wrote, which is
    what the rule referenced; whether ECS answers to them is Stage-13's question.
    """
    rule, mappings = mapped_text(REFERENCING_RULE)
    expected = [item.canonical_field for item in mappings.resolved if item.canonical_field]
    fields = seeds_of(REFERENCING_RULE).canonical_fields
    assert list(fields) == list(dict.fromkeys(expected))
    assert "process.name" in fields


def test_a_requirement_asks_with_its_text_and_nothing_resolved():
    query = requirement_query(REQUIREMENT, top_k=10)
    assert query.text == REQUIREMENT
    assert (query.entity_ids, query.canonical_fields) == ((), ())
    assert not query.is_empty


def test_both_seeds_take_the_stated_depth():
    rule, mappings = mapped()
    assert rule_query(rule, mappings, top_k=7).max_results == 7
    assert requirement_query(REQUIREMENT, top_k=7).max_results == 7


def test_neither_seed_states_anything_stage_thirteen_defaults():
    """Sources, sections, node types and hops are left as Stage-13 defines them."""
    rule, mappings = mapped()
    for query in (rule_query(rule, mappings, top_k=10), requirement_query(REQUIREMENT, top_k=10)):
        assert query.mode is RetrievalMode.HYBRID
        assert (query.sources, query.sections, query.node_types) == ((), (), ())
        assert query.max_hops is None


def test_the_service_seeds_a_rule_query_from_its_settings():
    rule, mappings = mapped()
    retriever = RecordingRetriever(fixtures.retrieval_result())
    service = RetrievalService.of(retriever, GraphRagSettings(top_k=3))
    service.for_rule(rule, mappings)
    assert retriever.queries[0] == rule_query(rule, mappings, top_k=3)


def test_the_service_seeds_a_requirement_query_from_its_settings():
    retriever = RecordingRetriever(fixtures.retrieval_result())
    service = RetrievalService.of(retriever, GraphRagSettings(top_k=3))
    service.for_requirement(REQUIREMENT)
    assert retriever.queries[0] == requirement_query(REQUIREMENT, top_k=3)


def test_the_service_returns_what_the_retriever_answered():
    result = fixtures.retrieval_result()
    service = RetrievalService.of(RecordingRetriever(result))
    assert service.for_requirement(REQUIREMENT) is result


def raw_mappings(query: str = RAW_QUERY):
    """Return the parsed rule and real mappings of one bare query."""
    parsed = parsed_rule_from_query(
        EngineRequest(
            ReasoningOperation.ANALYZE,
            user_id="u",
            query=query,
            language="kuery",
        )
    )
    return parsed, EntityMapper().map(EntityExtractor().extract(parsed))


def test_a_raw_query_seeds_retrieval_with_its_text_and_its_own_fields():
    """A query states fields, and those fields are what it asks the corpus about.

    The text is still carried, because the lexical route answers questions the
    graph route cannot. What changed is that the graph route now has something
    to ask with.
    """
    parsed, mappings = raw_mappings()
    query = rule_query(rule_context_from_parsed(parsed), mappings, top_k=10)
    assert query.text == RAW_QUERY
    assert query.canonical_fields == ("process.name", "process.command_line")
    assert not query.is_empty


def test_a_raw_query_still_resolves_no_identifier_of_its_own():
    """A field is not an identifier. Nothing here manufactures one.

    A bare query names fields and values; it names no ATT&CK technique, no CVE
    and no rule id. Seeding one would be inventing, which is why this stays
    empty even though the fields beside it no longer do.
    """
    parsed, mappings = raw_mappings()
    query = rule_query(rule_context_from_parsed(parsed), mappings, top_k=10)
    assert query.entity_ids == ()


def test_an_unresolved_mapping_never_becomes_a_retrieval_seed():
    """A field the clause reader could not pair carries 'query'; it must not seed.

    The separator proves a field was named, so the lexical sweep still reports
    it, but an unterminated group leaves the reader unable to say which values
    belonged to it. The mapping is therefore unresolved and carries the literal
    word, and seeding it would ask the corpus about a field called ``query``.
    """
    parsed, mappings = raw_mappings(
        "process.name:powershell.exe and winlog.task:(unclosed or list"
    )
    assert any(item.canonical_field == "query" for item in mappings.unresolved)
    query = rule_query(rule_context_from_parsed(parsed), mappings, top_k=10)
    assert "query" not in query.canonical_fields


def test_the_default_settings_are_stage_thirteen_own():
    assert RetrievalService.of(RecordingRetriever(fixtures.retrieval_result())).settings is (
        DEFAULT_SETTINGS
    )
    assert DEFAULT_SETTINGS == GraphRagSettings()
