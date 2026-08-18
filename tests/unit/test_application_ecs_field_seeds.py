"""Which unresolved field names may still ask the corpus a question.

Stage-10's alias table holds 72 names. It is a table of *spellings that share a
role* — that ``Image`` and ``process.executable`` mean the same thing — and it
was never meant to enumerate ECS. So a rule naming ``event.action`` maps to
nothing, and a field the corpus documents in full goes unasked: across the
187-rule measurement population, 388 of 438 unresolved field references name a
real ECS field.

Resolving and keying are different questions, and this is the second one. A
field name that *is* an ECS field identifies a record the corpus holds, whatever
the alias table thinks of it, and asking about it is exactly as sound as asking
about ``T1059.001``. A name that is not an ECS field stays unresolved and stays
reported — the contract Stage-13 makes about honesty is not weakened to gain
coverage.

Membership is settled against the ECS field-name set derived from the corpus at
build time. It is not a regex, not a second ontology and not a widened alias
table: the question asked is only whether a record with that exact field name
exists.
"""

from __future__ import annotations

from src.application.retrieval import rule_query
from src.context.models import RuleContext
from src.entities.models import Entity, ExtractedEntities
from src.entities.types import EntityType, RuleSection
from src.mapping.entity_mapper import EntityMapper
from src.mapping.models import MappedEntities
from src.mapping.types import CanonicalType
from src.parser.types import RuleFormat

# A small stand-in for the corpus set, holding only what the cases name.
ECS_FIELDS = frozenset(
    {
        "event.action",
        "event.category",
        "host.os.type",
        "process.name",
        "file.path",
        "destination.ip",
    }
)

MAPPER = EntityMapper()


def field(name: str) -> Entity:
    """Return the entity an Elastic query clause naming one field produces."""
    return Entity(
        entity_type=EntityType.FIELD,
        value=name,
        source_field=name,
        location="detection.query[0]",
        section=RuleSection.DETECTION,
        extractor="field",
    )


def value(entity_type: EntityType, raw: str, source_field: str) -> Entity:
    """Return a non-field entity, for the cases about what must not be seeded."""
    return Entity(
        entity_type=entity_type,
        value=raw,
        source_field=source_field,
        location="detection.query[0]",
        section=RuleSection.DETECTION,
        extractor="probe",
    )


def mapped(*entities: Entity) -> MappedEntities:
    """Return the real mapping of the entities given."""
    return MAPPER.map(
        ExtractedEntities(rule_format=RuleFormat.ELASTIC, entities=tuple(entities))
    )


def fields_of(*entities: Entity, ecs: frozenset[str] = ECS_FIELDS) -> tuple[str, ...]:
    """Return the canonical fields a rule made of these entities would ask with."""
    return rule_query(
        RuleContext(query="a query"), mapped(*entities), top_k=10, ecs_fields=ecs
    ).canonical_fields


def ids_of(*entities: Entity, ecs: frozenset[str] = ECS_FIELDS) -> tuple[str, ...]:
    """Return the entity identifiers a rule made of these entities would ask with."""
    return rule_query(
        RuleContext(query="a query"), mapped(*entities), top_k=10, ecs_fields=ecs
    ).entity_ids


# ------------------------------------------- 1-3. an unresolved ECS field seeds


def test_an_unresolved_event_action_becomes_a_seed():
    """``event.action`` is in no alias table and is a documented ECS field."""
    assert MAPPER.map_entity(field("event.action")).is_resolved is False
    assert fields_of(field("event.action")) == ("event.action",)


def test_an_unresolved_event_category_becomes_a_seed():
    assert fields_of(field("event.category")) == ("event.category",)


def test_an_unresolved_host_os_type_becomes_a_seed():
    assert fields_of(field("host.os.type")) == ("host.os.type",)


# --------------------------------------- 4. a name ECS does not carry does not


def test_a_vendor_field_absent_from_ecs_stays_unresolved():
    """``azure.activitylogs.operation_name`` is real, and is not ECS."""
    assert fields_of(field("azure.activitylogs.operation_name")) == ()


def test_a_field_absent_from_ecs_is_still_reported_as_an_entity():
    """Staying unseeded is not the same as being dropped."""
    entities = mapped(field("auditd.data.terminal"))

    assert [item.original.value for item in entities] == ["auditd.data.terminal"]
    assert entities.entities[0].is_resolved is False


# ------------------------------------------------------ 5. `query` never seeds

def test_the_literal_query_never_becomes_a_seed():
    """The unpairable-clause fallback writes ``query`` as the source field.

    It names the section a field was found in, not a field. It is not an ECS
    field name, so membership excludes it without a special case.
    """
    stray = Entity(
        entity_type=EntityType.FIELD,
        value="something.dotted",
        source_field="query",
        location="detection.query[0]",
        section=RuleSection.DETECTION,
        extractor="field",
    )

    assert "query" not in fields_of(stray)


# ------------------------------------------------ 6-7. F2 remains in force

def test_an_ip_network_is_still_not_a_seed():
    """Only the field mapper sets ``canonical_field``, so a value cannot arrive here."""
    entity = value(EntityType.IP_ADDRESS, "10.0.0.0/8", "source.ip")

    assert fields_of(entity) == ()
    assert ids_of(entity) == ()


def test_an_event_id_is_still_not_a_seed():
    entity = value(EntityType.WINDOWS_EVENT_ID, "4688", "event.code")

    assert fields_of(entity) == ()
    assert ids_of(entity) == ()


def test_an_attack_technique_is_still_a_seed():
    """The corpus-keyed types are untouched by any of this."""
    technique = value(EntityType.TAG, "T1059.001", "tags")

    assert ids_of(technique) == ("T1059.001",)


def test_a_cve_reference_type_is_still_corpus_keyed():
    from src.application.retrieval import CORPUS_KEYED_TYPES

    assert CanonicalType.CVE_REFERENCE in CORPUS_KEYED_TYPES
    assert CanonicalType.IP_NETWORK not in CORPUS_KEYED_TYPES


# ------------------------------------------- 8. resolved fields are unchanged

def test_a_resolved_alias_field_behaves_exactly_as_before():
    """``process.name`` resolves through the table and seeds as it always did."""
    assert MAPPER.map_entity(field("process.name")).is_resolved is True
    assert fields_of(field("process.name")) == ("process.name",)


def test_a_resolved_field_seeds_even_when_it_is_not_in_the_ecs_set():
    """Membership admits names; it never removes one the table already resolved.

    Sigma writes ``Image``, which the alias table resolves and ECS does not
    carry. It seeded before this change and it seeds after it.
    """
    assert fields_of(field("Image"), ecs=frozenset()) == ("Image",)


def test_an_empty_ecs_set_reproduces_the_previous_behaviour():
    """The default is inert, so a service built without the set is unaffected."""
    entities = (field("process.name"), field("event.action"))

    assert fields_of(*entities, ecs=frozenset()) == ("process.name",)


# ------------------------------------------------- 9. rule field order survives

def test_fields_are_asked_in_the_order_the_rule_named_them():
    """Resolved and newly-admitted fields interleave at their real positions."""
    ordered = fields_of(
        field("event.action"),
        field("process.name"),
        field("host.os.type"),
        field("file.path"),
    )

    assert ordered == ("event.action", "process.name", "host.os.type", "file.path")


def test_a_repeated_field_is_asked_once_at_its_first_position():
    ordered = fields_of(field("event.action"), field("process.name"), field("event.action"))

    assert ordered == ("event.action", "process.name")


# ------------------------------- 12. membership is ECS identity, not graph name

def test_membership_is_decided_by_the_ecs_field_set_alone():
    """A name the graph carries for some other node is not thereby an ECS field.

    ``Image`` is the name of the ATT&CK data source DS0007 and reaches that node
    through the graph's name index. That is a lookup, not an identity, and it is
    not what admits a field here: the ECS set does not contain ``image``, so
    membership does not admit it.
    """
    assert "image" not in {name.lower() for name in ECS_FIELDS}
    assert fields_of(field("Image")) == ("Image",)  # admitted by the alias table only


def test_a_dotted_name_is_not_admitted_merely_for_being_dotted():
    """No regex, no shape heuristic — only the exact set decides."""
    assert fields_of(field("not.an.ecs.field")) == ()
