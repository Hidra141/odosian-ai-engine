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
    DEFAULT_SETTINGS,
    RetrievalService,
    requirement_query,
    rule_query,
)
from src.context.context_builder import rule_context_from_parsed
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


def mapped():
    """Return the real mapped entities of the fixture rule."""
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    return rule_context_from_parsed(parsed), EntityMapper().map(
        EntityExtractor().extract(parsed)
    )


class RecordingRetriever:
    """A retriever that answers with one result and keeps every query."""

    def __init__(self, result: RetrievalResult) -> None:
        self.result = result
        self.queries: list[RetrievalQuery] = []

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        self.queries.append(query)
        return self.result


def test_a_rule_asks_with_its_resolved_identifiers():
    rule, mappings = mapped()
    query = rule_query(rule, mappings, top_k=10)
    expected = [item.canonical_id for item in mappings.resolved if item.canonical_id]
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
    rule, mappings = mapped()
    first = mappings.resolved[0]
    duplicated = dataclasses.replace(
        mappings,
        entities=(first, *mappings.entities, dataclasses.replace(first, canonical_id="T9999")),
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
    rule, mappings = mapped()
    without = dataclasses.replace(rule, query="")
    query = rule_query(without, mappings, top_k=10)
    assert query.text == ""
    assert not query.is_empty
    assert query.entity_ids


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


def test_a_raw_query_seeds_retrieval_with_its_text_and_nothing_resolved():
    """Nothing resolves from a bare query, so the lexical route carries it alone."""
    parsed = parsed_rule_from_query(
        EngineRequest(
            ReasoningOperation.ANALYZE,
            user_id="u",
            query=RAW_QUERY,
            language="kuery",
        )
    )
    mappings = EntityMapper().map(EntityExtractor().extract(parsed))
    query = rule_query(rule_context_from_parsed(parsed), mappings, top_k=10)
    assert query.text == RAW_QUERY
    assert (query.entity_ids, query.canonical_fields) == ((), ())
    assert not query.is_empty


def test_an_unresolved_mapping_never_becomes_a_retrieval_seed():
    """Unresolved entities carry canonical_field='query'; it must not be seeded."""
    parsed = parsed_rule_from_query(
        EngineRequest(
            ReasoningOperation.ANALYZE,
            user_id="u",
            query=RAW_QUERY,
            language="kuery",
        )
    )
    mappings = EntityMapper().map(EntityExtractor().extract(parsed))
    assert any(item.canonical_field == "query" for item in mappings.unresolved)
    query = rule_query(rule_context_from_parsed(parsed), mappings, top_k=10)
    assert "query" not in query.canonical_fields


def test_the_default_settings_are_stage_thirteen_own():
    assert RetrievalService.of(RecordingRetriever(fixtures.retrieval_result())).settings is (
        DEFAULT_SETTINGS
    )
    assert DEFAULT_SETTINGS == GraphRagSettings()
