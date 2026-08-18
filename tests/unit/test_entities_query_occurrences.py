"""Field and value extraction from a single query expression.

Stage-08 leaves an Elastic rule's detection as one query string, so the
occurrence traversal that Sigma's named blocks feed had nothing to walk and
every field-routed extractor returned nothing. What survived was shape scanning
and a lexical sweep for dotted names, which recognised ``powershell.exe`` as a
field because a lowercase filename and a dotted field name are the same shape.

These tests hold the query reader to the one thing it exists for: the pair. A
clause states a field and a value, and both must arrive on the entity with the
field in ``source_field`` — which is the key Stage-10 resolves against.

Nothing here asserts that the reader understands the query. Operators, grouping
and negation are the rule's meaning, and Stage-09 does not read meaning; a
clause it cannot pair is expected to yield nothing rather than a wrong pair.
"""

from __future__ import annotations

from src.entities.base_extractor import build_context, query_occurrences
from src.entities.extractor import EntityExtractor
from src.entities.types import EntityType, RuleSection
from src.parser.models import Detection, ParsedRule, RuleMetadata
from src.parser.parser import RuleParser
from src.parser.types import RuleFormat, RuleLanguage
from tests.fixtures import stage15 as fixtures

IODINE_QUERY = (
    "event.category:process and host.os.type:linux and "
    "event.type:(start or process_started) and process.name:(iodine or iodined)"
)
"""The query of ``Deprecated - Potential DNS Tunneling via Iodine``.

Copied from ``resources/knowledge/elastic/elastic.jsonl``, record
``elastic-rules:041d4d41-9589-43e2-ba13-5680af75ebc2``. A real rule rather than
an invented one, so the reader is held to syntax the corpus actually contains.
"""


def query_rule(query: str) -> ParsedRule:
    """Return the model an Elastic rule stating one query amounts to.

    Built directly rather than through the parser, so a query containing quotes
    is the string under test rather than one JSON has escaped and unescaped.
    """
    return ParsedRule(
        rule_format=RuleFormat.ELASTIC,
        metadata=RuleMetadata(title="probe"),
        detection=Detection(query=query, language=RuleLanguage.KUERY),
        source_text=query,
    )


def entities_of(query: str):
    """Return the entities extracted from a rule stating one query."""
    return EntityExtractor().extract(query_rule(query))


def pairs(query: str) -> list[tuple[str, str]]:
    """Return the ``(field, value)`` pairs the query reader finds."""
    return [(item.field, item.value) for item in query_occurrences(query)]


def sourced(entities, entity_type: EntityType) -> list[tuple[str, str]]:
    """Return ``(source_field, value)`` for every entity of one type."""
    return [
        (item.source_field, item.value)
        for item in entities
        if item.entity_type is entity_type
    ]


# --------------------------------------------------------------- TEST 1 and 2


def test_a_bare_value_keeps_its_field():
    assert pairs("process.name:powershell.exe") == [("process.name", "powershell.exe")]


def test_a_quoted_value_loses_only_its_quotes():
    assert pairs('process.name:"powershell.exe"') == [
        ("process.name", "powershell.exe")
    ]


def test_a_spaced_separator_is_the_same_clause():
    assert pairs("process.name : powershell.exe") == [
        ("process.name", "powershell.exe")
    ]


def test_the_field_reaches_the_entity_as_its_source_field():
    entities = entities_of("process.name:powershell.exe")
    assert sourced(entities, EntityType.PROCESS) == [
        ("process.name", "powershell.exe")
    ]


def test_a_quoted_value_reaches_the_entity_unquoted():
    entities = entities_of('process.name:"powershell.exe"')
    assert sourced(entities, EntityType.PROCESS) == [
        ("process.name", "powershell.exe")
    ]


def test_a_value_is_no_longer_reported_as_a_field():
    values = [
        item.value
        for item in entities_of('process.name:"powershell.exe"')
        if item.entity_type is EntityType.FIELD
    ]
    assert "powershell.exe" not in values


# --------------------------------------------------------------------- TEST 3


def test_a_wildcard_value_is_carried_through_untouched():
    assert pairs("process.command_line:*-enc*") == [
        ("process.command_line", "*-enc*")
    ]


def test_a_wildcard_command_line_reaches_the_command_extractor():
    entities = entities_of("process.command_line:*-enc*")
    assert sourced(entities, EntityType.COMMAND_LINE) == [
        ("process.command_line", "*-enc*")
    ]


# --------------------------------------------------------------------- TEST 4


def test_a_parenthesised_list_yields_one_pair_per_member():
    assert pairs("process.name:(iodine or iodined)") == [
        ("process.name", "iodine"),
        ("process.name", "iodined"),
    ]


def test_every_member_of_a_list_carries_the_same_source_field():
    entities = entities_of("process.name:(iodine or iodined)")
    assert sourced(entities, EntityType.PROCESS) == [
        ("process.name", "iodine"),
        ("process.name", "iodined"),
    ]


def test_the_keywords_joining_a_list_are_not_values():
    values = [value for _, value in pairs("event.type:(start or process_started)")]
    assert values == ["start", "process_started"]


def test_members_of_one_list_are_addressed_separately():
    locations = [item.location for item in query_occurrences("process.name:(a or b)")]
    assert len(set(locations)) == 2


# --------------------------------------------------------------------- TEST 5


def test_a_network_list_keeps_its_field_on_every_address():
    assert pairs("source.ip:(10.0.0.0/8 or 192.168.0.0/16)") == [
        ("source.ip", "10.0.0.0/8"),
        ("source.ip", "192.168.0.0/16"),
    ]


def test_addresses_reach_the_network_extractor_with_their_field():
    entities = entities_of("source.ip:(10.0.0.0/8 or 192.168.0.0/16)")
    routed = [
        (item.source_field, item.value)
        for item in entities
        if item.entity_type is EntityType.IP_ADDRESS and item.source_field == "source.ip"
    ]
    assert routed == [
        ("source.ip", "10.0.0.0/8"),
        ("source.ip", "192.168.0.0/16"),
    ]


def test_shape_scanning_still_finds_the_same_addresses():
    entities = entities_of("source.ip:(10.0.0.0/8 or 192.168.0.0/16)")
    scanned = [
        item.value
        for item in entities
        if item.entity_type is EntityType.IP_ADDRESS and item.source_field == "query"
    ]
    assert scanned == ["10.0.0.0/8", "192.168.0.0/16"]


def test_a_hash_in_a_query_is_still_found_by_shape():
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    entities = entities_of(f"file.hash.sha256:{digest}")
    assert digest in [
        item.value for item in entities if item.entity_type is EntityType.FILE_HASH
    ]


# ------------------------------------------------------- operators and refusal


def test_a_negated_clause_still_states_its_pair():
    assert pairs("process.name != powershell.exe") == [
        ("process.name", "powershell.exe")
    ]


def test_a_not_keyword_is_not_mistaken_for_the_value():
    assert pairs("process.name:not powershell.exe") == [
        ("process.name", "powershell.exe")
    ]


def test_a_keyword_is_never_read_as_a_field():
    fields = {field for field, _ in pairs("a:1 and b:2 or c:3 not d:4")}
    assert fields == {"a", "b", "c", "d"}


def test_an_unclosed_group_yields_nothing_rather_than_a_wrong_pair():
    assert pairs("process.name:(iodine or iodined") == []


def test_an_empty_query_yields_nothing():
    assert pairs("") == []


def test_the_reader_is_deterministic():
    assert query_occurrences(IODINE_QUERY) == query_occurrences(IODINE_QUERY)


def test_every_occurrence_of_one_query_is_addressed_uniquely():
    locations = [item.location for item in query_occurrences(IODINE_QUERY)]
    assert len(set(locations)) == len(locations)


def test_a_query_occurrence_is_recorded_in_the_detection_section():
    assert all(
        item.section is RuleSection.DETECTION for item in query_occurrences(IODINE_QUERY)
    )


# ----------------------------------------------------------- the real corpus rule


def test_the_iodine_rule_states_every_pair_it_carries():
    assert pairs(IODINE_QUERY) == [
        ("event.category", "process"),
        ("host.os.type", "linux"),
        ("event.type", "start"),
        ("event.type", "process_started"),
        ("process.name", "iodine"),
        ("process.name", "iodined"),
    ]


def test_the_iodine_rule_yields_both_process_names():
    entities = entities_of(IODINE_QUERY)
    assert sourced(entities, EntityType.PROCESS) == [
        ("process.name", "iodine"),
        ("process.name", "iodined"),
    ]


# --------------------------------------------------------------------- TEST 6


SIGMA_ENTITIES = (
    (EntityType.PROCESS, "powershell.exe", "process.name"),
    (EntityType.COMMAND_LINE, "-enc", "process.command_line|contains"),
    (EntityType.FIELD, "process.name", "process.name"),
    (EntityType.FIELD, "process.command_line", "process.command_line|contains"),
    (EntityType.FIELD_MODIFIER, "contains", "process.command_line|contains"),
    (EntityType.SEVERITY, "medium", "severity"),
    (EntityType.STATUS, "experimental", "status"),
    (EntityType.PRODUCT, "windows", "product"),
    (EntityType.CATEGORY, "process_creation", "category"),
)
"""What the Sigma fixture extracted before the query reader existed.

Recorded as the whole list in order, not as a count, so a change that adds or
reorders an entity fails here rather than passing on an unchanged total.
"""


def test_the_sigma_fixture_extracts_exactly_what_it_always_did():
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    extracted = tuple(
        (item.entity_type, item.value, item.source_field)
        for item in EntityExtractor().extract(parsed)
    )
    assert extracted == SIGMA_ENTITIES


def test_a_sigma_rule_reaches_the_query_reader_not_at_all():
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    assert parsed.detection.query is None
    assert query_occurrences(parsed.detection.query or "") == ()


def test_a_sigma_context_holds_only_its_own_occurrences():
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    context = build_context(parsed)
    assert all(
        item.location.startswith("detection.selection")
        for item in context.occurrences
    )


# ------------------------------------------------------- C1: the caseless subfield


def test_a_caseless_subfield_reads_as_its_base_field():
    assert pairs('process.name.caseless:"lsass.exe"') == [
        ("process.name.caseless", "lsass.exe")
    ]


def test_a_caseless_subfield_restores_the_value_entity():
    """The subfield cost the value, not only the field.

    ``process.name.caseless`` misses every routing table, so the executable the
    clause names was reaching no extractor at all.
    """
    entities = entities_of('process.name.caseless:"lsass.exe"')
    assert sourced(entities, EntityType.PROCESS) == [
        ("process.name.caseless", "lsass.exe")
    ]


def test_a_caseless_subfield_reports_the_base_as_the_field():
    values = [
        item.value
        for item in entities_of('process.name.caseless:"lsass.exe"')
        if item.entity_type is EntityType.FIELD
    ]
    assert values == ["process.name"]


def test_a_caseless_subfield_is_recorded_as_a_modifier():
    modifiers = [
        item.value
        for item in entities_of('process.name.caseless:"lsass.exe"')
        if item.entity_type is EntityType.FIELD_MODIFIER
    ]
    assert modifiers == ["caseless"]


def test_a_caseless_subfield_keeps_what_the_rule_wrote():
    """``source_field`` states the rule's own spelling, as it does for Sigma."""
    entities = entities_of('process.name.caseless:"lsass.exe"')
    assert all(
        item.source_field == "process.name.caseless"
        for item in entities
        if item.entity_type
        in (EntityType.PROCESS, EntityType.FIELD, EntityType.FIELD_MODIFIER)
    )


def test_normalising_a_subfield_does_not_touch_the_query():
    query = 'process.name.caseless:"lsass.exe"'
    parsed = query_rule(query)
    EntityExtractor().extract(parsed)
    assert parsed.detection.query == query
    assert parsed.source_text == query


def test_a_plain_field_is_unaffected_by_subfield_handling():
    entities = entities_of('process.name:"lsass.exe"')
    assert sourced(entities, EntityType.PROCESS) == [("process.name", "lsass.exe")]
    assert [
        item.value for item in entities if item.entity_type is EntityType.FIELD
    ] == ["process.name"]


def test_a_keyword_subfield_is_not_normalised():
    """No occurrence of it exists in the corpus, so nothing is guessed about it."""
    values = [
        item.value
        for item in entities_of('process.name.keyword:"lsass.exe"')
        if item.entity_type is EntityType.FIELD
    ]
    assert values == ["process.name.keyword"]


def test_a_text_subfield_is_not_normalised():
    values = [
        item.value
        for item in entities_of('process.name.text:"lsass.exe"')
        if item.entity_type is EntityType.FIELD
    ]
    assert values == ["process.name.text"]


def test_an_unrelated_dotted_tail_is_not_stripped():
    values = [
        item.value
        for item in entities_of('process.name.something:"x"')
        if item.entity_type is EntityType.FIELD
    ]
    assert values == ["process.name.something"]


# ------------------------------------ C2: a dotted token is a field only in a clause


def test_a_dotted_value_is_not_reported_as_a_field():
    """``lsass.exe`` standing alone is a value; nothing follows it to make it a field."""
    values = [
        item.value
        for item in entities_of("process.name:x and lsass.exe")
        if item.entity_type is EntityType.FIELD
    ]
    assert values == ["process.name"]


def test_a_dotted_token_a_clause_could_not_be_read_from_is_still_reported():
    """The sweep stays a safety net for a clause the reader refused to pair.

    An unclosed group means ``query_occurrences`` yields nothing for it, yet the
    separator proves a field was named. It is still reported, on ``query``,
    because the sweep cannot say which field the values belonged to.
    """
    entities = entities_of("spec.containers.image:(unclosed or list")
    reported = [
        (item.value, item.source_field)
        for item in entities
        if item.entity_type is EntityType.FIELD
    ]
    assert reported == [("spec.containers.image", "query")]


def test_a_hostname_in_a_value_list_is_not_a_field():
    """The list states one field twice, and neither host is one of them.

    One field entity per occurrence is the arrangement Sigma has always had — a
    key with two values yields two — so the field is expected twice here.
    """
    values = [
        item.value
        for item in entities_of("destination.domain:(blogspot.com or sharepoint.com)")
        if item.entity_type is EntityType.FIELD
    ]
    assert set(values) == {"destination.domain"}
    assert values == ["destination.domain", "destination.domain"]


def test_the_phase_two_stated_behaviour_is_preserved():
    """A clause value was already suppressed, and still is."""
    values = [
        item.value
        for item in entities_of('process.name:"powershell.exe" and process.args:cmd.exe')
        if item.entity_type is EntityType.FIELD
    ]
    assert values == ["process.name", "process.args"]


def test_genuine_dotted_fields_all_survive_the_narrowing():
    query = (
        "process.name:a and process.command_line:b and file.path:c and "
        "source.ip:d and destination.ip:e"
    )
    values = [
        item.value
        for item in entities_of(query)
        if item.entity_type is EntityType.FIELD
    ]
    assert values == [
        "process.name",
        "process.command_line",
        "file.path",
        "source.ip",
        "destination.ip",
    ]
