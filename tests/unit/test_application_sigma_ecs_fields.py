"""Asking the corpus about a Sigma field by the name the corpus knows it under.

Sigma writes Windows telemetry spellings — ``Image``, ``CommandLine``,
``EventID`` — and Stage-10's alias table already recognises them: it knows
``Image`` occupies the process-image role. What it does not do, and says so, is
resolve them against ECS; it records that several spellings share a role, not
which ECS field documents them. So the name that reached retrieval was the one
the rule wrote, and the corpus holds no record under it. ``CommandLine`` asked
for a field nothing answers to, and ``Image`` reached the ATT&CK data source of
that name instead of ``process.executable``.

Elastic never showed this because its rules already write ECS names, so the
rule's spelling and the corpus's name happened to be the same string.

The correspondence is keyed on the **spelling**, not on the canonical type. A
type is a role and a role covers several fields: ``Image`` and ``ParentImage``
share ``PROCESS_IMAGE_FIELD`` while naming ``process.executable`` and
``process.parent.executable``, and ``NETWORK_FIELD`` alone spans seven ECS
fields. Only the spelling says which one was meant.

Translation happens where the query is assembled, because that is where the ECS
vocabulary already lives and where the field order ranking reads is fixed. The
mapping itself is untouched: an entity still records what the rule wrote.
"""

from __future__ import annotations

from src.application.retrieval import (
    CORPUS_KEYED_TYPES,
    SIGMA_FIELD_NAMES,
    rule_query,
)
from src.context.models import RuleContext
from src.entities.base_extractor import split_field
from src.entities.models import Entity, ExtractedEntities
from src.entities.types import EntityType, RuleSection
from src.mapping.entity_mapper import EntityMapper
from src.mapping.field_mapper import FieldMapper
from src.mapping.models import MappedEntities
from src.mapping.types import CanonicalType
from src.parser.types import RuleFormat

MAPPER = EntityMapper()

ECS_FIELDS = frozenset(
    {
        "process.executable",
        "process.parent.executable",
        "process.command_line",
        "process.parent.command_line",
        "process.name",
        "process.working_directory",
        "process.pe.original_file_name",
        "event.code",
        "event.provider",
        "event.action",
        "file.path",
        "file.name",
        "file.directory",
        "registry.path",
        "registry.value",
        "destination.ip",
        "destination.domain",
        "source.ip",
        "user.name",
        "group.name",
        "network.protocol",
    }
)


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


def value(entity_type: EntityType, raw: str, source_field: str) -> Entity:
    """Return a non-field entity, for the cases about what must not be seeded."""
    return Entity(
        entity_type=entity_type,
        value=raw,
        source_field=source_field,
        location="detection.selection[0]",
        section=RuleSection.DETECTION,
        extractor="probe",
    )


def mapped(*entities: Entity) -> MappedEntities:
    """Return the real mapping of the entities given."""
    return MAPPER.map(
        ExtractedEntities(rule_format=RuleFormat.SIGMA, entities=tuple(entities))
    )


def fields_of(*entities: Entity, ecs: frozenset[str] = ECS_FIELDS) -> tuple[str, ...]:
    """Return the canonical fields a rule made of these entities asks with."""
    return rule_query(
        RuleContext(query="a query"), mapped(*entities), top_k=10, ecs_fields=ecs
    ).canonical_fields


def ids_of(*entities: Entity, ecs: frozenset[str] = ECS_FIELDS) -> tuple[str, ...]:
    """Return the entity identifiers a rule made of these entities asks with."""
    return rule_query(
        RuleContext(query="a query"), mapped(*entities), top_k=10, ecs_fields=ecs
    ).entity_ids


# ------------------------------------------------ 1-4. the named Sigma fields


def test_image_asks_about_process_executable():
    assert fields_of(field("Image")) == ("process.executable",)


def test_parent_image_asks_about_the_parent_field():
    """The case that proves the correspondence is keyed on the spelling.

    ``Image`` and ``ParentImage`` share one canonical type, so a type-keyed
    table could not tell them apart.
    """
    assert fields_of(field("ParentImage")) == ("process.parent.executable",)
    assert (
        FieldMapper().map(field("Image")).canonical_type
        is FieldMapper().map(field("ParentImage")).canonical_type
    )


def test_command_line_asks_about_process_command_line():
    assert fields_of(field("CommandLine")) == ("process.command_line",)


def test_event_id_asks_about_event_code():
    assert fields_of(field("EventID")) == ("event.code",)


def test_a_sigma_rule_asks_about_every_field_it_names():
    ordered = fields_of(field("Image"), field("CommandLine"), field("ParentImage"))

    assert ordered == (
        "process.executable",
        "process.command_line",
        "process.parent.executable",
    )


def test_two_spellings_of_one_field_are_asked_once():
    """``Image`` and ``process.executable`` name the same field."""
    assert fields_of(field("Image"), field("process.executable")) == ("process.executable",)


# --------------------------------------------- 5-6. unmapped and excluded


def test_an_unmapped_sigma_field_is_left_as_the_rule_wrote_it():
    """``ScriptBlockText`` is in the alias table but ECS documents no such field."""
    assert "scriptblocktext" not in SIGMA_FIELD_NAMES
    assert fields_of(field("ScriptBlockText")) == ("ScriptBlockText",)


def test_a_field_outside_the_alias_table_and_outside_ecs_asks_nothing():
    assert fields_of(field("auditd.data.terminal")) == ()


def test_the_ambiguous_spellings_are_never_translated():
    """``source``, ``type`` and ``service`` name more than one role.

    Stage-10 leaves them unresolved rather than choosing, and nothing here
    overrides that.
    """
    for name in ("source", "type", "service"):
        assert name not in SIGMA_FIELD_NAMES
        assert fields_of(field(name)) == ()


def test_channel_and_logname_are_not_translated():
    """Their ECS counterpart is not a field this corpus documents uniquely."""
    for name in ("channel", "logname"):
        assert name not in SIGMA_FIELD_NAMES


def test_hashes_is_not_translated():
    """A Sysmon composite carrying several digests answers to no single field."""
    assert "hashes" not in SIGMA_FIELD_NAMES


def test_a_correspondence_whose_target_the_corpus_lacks_is_not_used():
    """Membership is checked against the corpus, so the table cannot invent a field."""
    assert fields_of(field("Image"), ecs=frozenset({"process.name"})) == ("Image",)


# ------------------------------------------------- 7. Elastic is unaffected


def test_an_elastic_ecs_native_field_is_unchanged():
    assert fields_of(field("process.name")) == ("process.name",)
    assert fields_of(field("file.path")) == ("file.path",)
    assert fields_of(field("destination.ip")) == ("destination.ip",)


def test_an_elastic_field_outside_the_alias_table_still_seeds_through_c3():
    """C3's behaviour is untouched: an unresolved name that ECS documents seeds."""
    assert fields_of(field("event.action")) == ("event.action",)


def test_elastic_field_order_is_preserved():
    ordered = fields_of(field("event.action"), field("process.name"), field("file.path"))

    assert ordered == ("event.action", "process.name", "file.path")


# --------------------------------------------------- 8. F2 remains in force


def test_an_ip_address_is_still_not_a_seed():
    entity = value(EntityType.IP_ADDRESS, "10.0.0.0/8", "source.ip")

    assert fields_of(entity) == ()
    assert ids_of(entity) == ()


def test_a_windows_event_id_value_is_still_not_a_seed():
    entity = value(EntityType.WINDOWS_EVENT_ID, "4688", "EventID")

    assert fields_of(entity) == ()
    assert ids_of(entity) == ()


def test_an_attack_technique_is_still_a_seed():
    assert ids_of(value(EntityType.TAG, "T1059.001", "tags")) == ("T1059.001",)


def test_the_corpus_keyed_types_are_unchanged():
    assert CanonicalType.CVE_REFERENCE in CORPUS_KEYED_TYPES
    assert CanonicalType.IP_NETWORK not in CORPUS_KEYED_TYPES
    assert len(CORPUS_KEYED_TYPES) == 5


# ------------------------------------------------------ 9-10. C1 and C2


def test_c1_a_caseless_subfield_still_reaches_its_base_field():
    """``process.name.caseless`` is still read as ``process.name``."""
    assert split_field("process.name.caseless") == ("process.name", ("caseless",))
    assert fields_of(field("process.name", "process.name.caseless")) == ("process.name",)


def test_c1_a_caseless_sigma_spelling_is_translated_from_its_base():
    assert fields_of(field("Image", "Image.caseless")) == ("process.executable",)


def test_c1_keyword_and_text_are_still_left_alone():
    assert split_field("file.path.keyword") == ("file.path.keyword", ())
    assert split_field("message.text") == ("message.text", ())


def test_c2_a_sigma_modifier_still_reaches_the_base_field():
    """``Image|endswith`` is still the field ``Image``."""
    assert split_field("Image|endswith") == ("Image", ("endswith",))
    assert fields_of(field("Image", "Image|endswith")) == ("process.executable",)


def test_the_mapping_still_records_what_the_rule_wrote():
    """FieldMapper semantics are untouched — only the query is translated."""
    entity = field("Image", "Image|endswith")
    mapping = FieldMapper().map(entity)

    assert mapping.canonical_field == "Image"
    assert mapping.canonical_type is CanonicalType.PROCESS_IMAGE_FIELD
    assert mapping.modifiers == ("endswith",)
    assert mapping.provenance.source_field == "Image|endswith"
    assert mapping.original.value == "Image"


# ---------------------------------------------------------- 11-12. C3 / order


def test_c3_an_unresolved_ecs_field_still_seeds():
    assert fields_of(field("host.os.type"), ecs=frozenset({"host.os.type"})) == (
        "host.os.type",
    )


def test_the_query_carries_ecs_names_so_the_tie_break_can_use_them():
    """Ranking orders tied ECS candidates by their position in this tuple.

    The names here must therefore be the ones the seeds will match on, which is
    why the translation happens when the query is built and not later.
    """
    ordered = fields_of(field("CommandLine"), field("Image"))

    assert ordered == ("process.command_line", "process.executable")
    assert all(name in ECS_FIELDS for name in ordered)


def test_translation_is_deterministic():
    entities = (field("Image"), field("EventID"), field("CommandLine"))

    assert fields_of(*entities) == fields_of(*entities)


# ------------------------------------------------- 13. the correspondence itself


def test_every_correspondence_target_differs_from_its_key():
    """A key that already is its target would be a table entry doing nothing."""
    for spelling, ecs_name in SIGMA_FIELD_NAMES.items():
        assert spelling != ecs_name
        assert spelling == spelling.lower()


def test_the_correspondence_covers_the_named_sigma_fields():
    for spelling, expected in (
        ("image", "process.executable"),
        ("parentimage", "process.parent.executable"),
        ("commandline", "process.command_line"),
        ("eventid", "event.code"),
    ):
        assert SIGMA_FIELD_NAMES[spelling] == expected


# --------------------------------------- 14. the spelling the rule wrote

# Every case above asks what the *graph* is told. These ask what the index is
# told about the same rule, at the same call sites, because the pair is the
# claim: the translation is only sound while the original survives beside it.


def lexical_of(*entities: Entity, ecs: frozenset[str] = ECS_FIELDS) -> tuple[str, ...]:
    """Return the field spellings a rule made of these entities asks the index."""
    return rule_query(
        RuleContext(query="a query"), mapped(*entities), top_k=10, ecs_fields=ecs
    ).lexical_fields


def test_the_index_is_asked_for_image_by_that_name():
    assert lexical_of(field("Image")) == ("Image",)


def test_the_index_is_asked_for_command_line_by_that_name():
    assert lexical_of(field("CommandLine")) == ("CommandLine",)


def test_the_index_is_asked_for_event_id_by_that_name():
    assert lexical_of(field("EventID")) == ("EventID",)


def test_every_spelling_in_the_table_survives_in_the_lexical_list():
    """The whole correspondence table, checked from both ends at once.

    Whatever the graph is told, the index is told the spelling that was
    written. Where the table's target is one this fixture's ECS set documents,
    the two lists differ — that is the translation happening; where it is not,
    they agree, because :func:`_ecs_name` never uses a name the corpus lacks.
    """
    for spelling, ecs_name in SIGMA_FIELD_NAMES.items():
        assert lexical_of(field(spelling)) == (spelling,)
        expected = (ecs_name,) if ecs_name in ECS_FIELDS else (spelling,)
        assert fields_of(field(spelling)) == expected


def test_the_untranslated_spellings_are_the_same_in_both_lists():
    for name in ("Channel", "LogName", "Hashes", "ScriptBlockText"):
        assert lexical_of(field(name)) == fields_of(field(name))


def test_the_ambiguous_spellings_reach_neither_list():
    for name in ("Source", "Type", "Service"):
        assert lexical_of(field(name)) == ()
        assert fields_of(field(name)) == ()


def test_c1_the_lexical_list_carries_the_base_field_not_the_subfield():
    entity = field("process.name", source_field="process.name.caseless")

    assert lexical_of(entity) == ("process.name",)
    assert fields_of(entity) == ("process.name",)


def test_c2_a_modifier_is_not_part_of_the_spelling_the_index_is_asked_with():
    entity = field("CommandLine", source_field="CommandLine|contains")

    assert lexical_of(entity) == ("CommandLine",)
    assert fields_of(entity) == ("process.command_line",)


def test_an_elastic_rule_asks_the_index_and_the_graph_the_same_thing():
    for name in ("process.name", "process.command_line", "event.code"):
        assert lexical_of(field(name)) == fields_of(field(name)) == (name,)


def test_the_mapping_still_records_what_the_rule_wrote_alongside_both():
    entity = field("Image", source_field="Image|endswith")
    mappings = mapped(entity)

    assert mappings.entities[0].canonical_field == "Image"
    assert mappings.entities[0].original.source_field == "Image|endswith"
    assert lexical_of(entity) == ("Image",)
    assert fields_of(entity) == ("process.executable",)
