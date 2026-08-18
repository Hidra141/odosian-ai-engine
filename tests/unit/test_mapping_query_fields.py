"""What a query's fields resolve to, and what they ask the corpus.

Stage-10 resolves a field entity against ``source_field``. While a query's
fields arrived carrying the literal string ``query``, every one of them missed
the alias table, became unresolved, and was dropped by Stage-13's seeding —
which filters on resolved entities. An Elastic rule therefore asked the corpus
about nothing it referenced.

These tests check the two ends of that: the mapper receives the field the rule
wrote, and the canonical field it establishes reaches the retrieval query.

The Sigma cases sit beside the Elastic ones deliberately. Both formats resolve
through the same alias table, and the point of the correction is that they now
reach it the same way.
"""

from __future__ import annotations

from src.application.retrieval import rule_query
from src.context.context_builder import rule_context_from_parsed
from src.entities.extractor import EntityExtractor
from src.entities.models import Entity
from src.entities.types import EntityType, RuleSection
from src.mapping.entity_mapper import EntityMapper
from src.mapping.field_mapper import FieldMapper
from src.mapping.types import CanonicalType, MappingStatus
from src.parser.models import Detection, ParsedRule, RuleMetadata
from src.parser.parser import RuleParser
from src.parser.types import RuleFormat, RuleLanguage
from tests.fixtures import stage15 as fixtures

IODINE_QUERY = (
    "event.category:process and host.os.type:linux and "
    "event.type:(start or process_started) and process.name:(iodine or iodined)"
)
"""The query of ``elastic-rules:041d4d41-9589-43e2-ba13-5680af75ebc2``."""


def query_rule(query: str) -> ParsedRule:
    """Return a parsed Elastic rule stating one query."""
    return ParsedRule(
        rule_format=RuleFormat.ELASTIC,
        metadata=RuleMetadata(title="probe"),
        detection=Detection(query=query, language=RuleLanguage.KUERY),
        source_text=query,
    )


def mapped_of(query: str):
    """Return the real mapped entities of a rule stating one query."""
    parsed = query_rule(query)
    return parsed, EntityMapper().map(EntityExtractor().extract(parsed))


def field_entity(source_field: str, value: str) -> Entity:
    """Return a field entity as the query reader would produce one."""
    return Entity(
        entity_type=EntityType.FIELD,
        value=value,
        source_field=source_field,
        location="detection.query[0]",
        section=RuleSection.DETECTION,
        extractor="field",
    )


def canonical_fields(query: str) -> tuple[str, ...]:
    """Return the canonical fields a query's rule asks the corpus about."""
    parsed, mappings = mapped_of(query)
    return rule_query(
        rule_context_from_parsed(parsed), mappings, top_k=10
    ).canonical_fields


# --------------------------------------------------------------------- TEST 7


def test_the_mapper_resolves_a_process_name_field():
    mapped = FieldMapper().map(field_entity("process.name", "process.name"))
    assert mapped.canonical_field == "process.name"
    assert mapped.canonical_type is CanonicalType.PROCESS_NAME_FIELD
    assert mapped.status is MappingStatus.ALIAS


def test_the_mapper_resolves_a_command_line_field():
    mapped = FieldMapper().map(
        field_entity("process.command_line", "process.command_line")
    )
    assert mapped.canonical_field == "process.command_line"
    assert mapped.canonical_type is CanonicalType.COMMAND_LINE_FIELD


def test_no_mapping_is_keyed_on_the_word_query():
    _, mappings = mapped_of('process.name:"powershell.exe"')
    assert "query" not in {item.canonical_field for item in mappings}


def test_a_query_field_is_no_longer_unresolved():
    _, mappings = mapped_of('process.name:"powershell.exe"')
    resolved = {
        item.canonical_field
        for item in mappings.resolved
        if item.canonical_type is CanonicalType.PROCESS_NAME_FIELD
    }
    assert resolved == {"process.name"}


def test_a_field_outside_the_alias_table_stays_unresolved():
    mapped = FieldMapper().map(field_entity("event.category", "event.category"))
    assert mapped.status is MappingStatus.UNRESOLVED
    assert mapped.canonical_field == "event.category"


# --------------------------------------------------------------------- TEST 9


def test_a_query_rule_asks_the_corpus_about_its_own_fields():
    assert canonical_fields('process.name:"powershell.exe"') == ("process.name",)


def test_both_fields_of_the_fixture_query_reach_retrieval():
    assert canonical_fields(fixtures.RULE_QUERY) == (
        "process.name",
        "process.command_line",
    )


def test_the_iodine_rule_asks_about_the_field_it_matches_on():
    assert "process.name" in canonical_fields(IODINE_QUERY)


def test_a_repeated_field_is_asked_about_once():
    assert canonical_fields("process.name:(iodine or iodined)") == ("process.name",)


def test_seeds_are_stated_in_first_seen_order():
    query = "process.command_line:*-enc* and process.name:powershell.exe"
    assert canonical_fields(query) == ("process.command_line", "process.name")


# ----------------------------------------------------------- Sigma regression


def test_the_sigma_fixture_still_asks_about_its_own_fields():
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    mappings = EntityMapper().map(EntityExtractor().extract(parsed))
    seeds = rule_query(rule_context_from_parsed(parsed), mappings, top_k=10)
    assert seeds.canonical_fields == ("process.name", "process.command_line")


def test_the_sigma_fixture_maps_exactly_what_it_always_did():
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    mappings = EntityMapper().map(EntityExtractor().extract(parsed))
    assert tuple(
        (item.canonical_type, item.canonical_field, item.status) for item in mappings
    ) == (
        (CanonicalType.PROCESS, None, MappingStatus.EXACT),
        (CanonicalType.COMMAND_LINE, None, MappingStatus.EXACT),
        (CanonicalType.PROCESS_NAME_FIELD, "process.name", MappingStatus.ALIAS),
        (
            CanonicalType.COMMAND_LINE_FIELD,
            "process.command_line",
            MappingStatus.ALIAS,
        ),
        (CanonicalType.FIELD_MODIFIER, None, MappingStatus.EXACT),
        (CanonicalType.SEVERITY_LEVEL, None, MappingStatus.EXACT),
        (CanonicalType.RULE_STATUS, None, MappingStatus.EXACT),
        (CanonicalType.LOG_PRODUCT, None, MappingStatus.EXACT),
        (CanonicalType.LOG_CATEGORY, None, MappingStatus.EXACT),
    )


# --------------------------------------------------- the caseless subfield (C1)


def test_a_caseless_subfield_resolves_as_its_base_field():
    mapped = FieldMapper().map(field_entity("process.name.caseless", "process.name"))
    assert mapped.canonical_field == "process.name"
    assert mapped.canonical_type is CanonicalType.PROCESS_NAME_FIELD
    assert mapped.status is MappingStatus.ALIAS


def test_a_caseless_subfield_records_the_subfield_as_a_modifier():
    mapped = FieldMapper().map(field_entity("process.name.caseless", "process.name"))
    assert mapped.modifiers == ("caseless",)


def test_a_caseless_query_asks_the_corpus_about_the_base_field():
    assert canonical_fields('process.name.caseless:"lsass.exe"') == ("process.name",)


def test_a_keyword_subfield_still_does_not_resolve():
    mapped = FieldMapper().map(field_entity("process.name.keyword", "process.name"))
    assert mapped.status is MappingStatus.UNRESOLVED
    assert mapped.canonical_field == "process.name.keyword"
