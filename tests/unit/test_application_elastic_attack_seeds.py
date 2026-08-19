"""What an Elastic rule's ATT&CK references reach, and what they must not.

Reading the threat section gives an Elastic rule identifiers it never had. Those
identifiers travel the route Sigma's have always travelled — tag entity,
reference mapper, ``entity_ids`` — so the question these tests answer is not
whether that route works, which Sigma already proves, but whether anything else
moved when Elastic joined it.

Four things must not move. F2 still admits only the canonical types that name
something the corpus holds, so a technique seeds and a tactic name or a severity
does not. Phase 5D's two vocabularies stay apart: ``canonical_fields`` keeps ECS
names, ``lexical_fields`` keeps what the rule wrote, and an ATT&CK identifier is
neither — it is an entity, and it belongs in ``entity_ids``. The Phase 3F
tie-break still reads the canonical field order. And a Sigma rule asks exactly
what it asked before, because nothing on its path changed.
"""

from __future__ import annotations

import json

from src.application.retrieval import rule_query
from src.context.context_builder import rule_context_from_parsed
from src.entities.extractor import EntityExtractor
from src.mapping.entity_mapper import EntityMapper
from src.mapping.types import CanonicalType
from src.parser.parser import RuleParser
from src.parser.types import RuleFormat

PARSER = RuleParser()
EXTRACTOR = EntityExtractor()
MAPPER = EntityMapper()

ECS_FIELDS = frozenset(
    {
        "process.name",
        "process.command_line",
        "process.executable",
        "event.code",
        "file.path",
    }
)

ELASTIC = {
    "name": "Suspicious Interpreter",
    "rule_id": "8a1f2c34-0000-4c11-9f00-2b7a5c9e1234",
    "query": 'process.name : "powershell.exe" and process.command_line : *-enc*',
    "language": "kuery",
    "type": "query",
    "index": ["logs-endpoint.events.process-*"],
    "tags": ["Elastic", "Host"],
    "threat": [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0002", "name": "Execution"},
            "technique": [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "subtechnique": [{"id": "T1059.001", "name": "PowerShell"}],
                }
            ],
        }
    ],
}

SIGMA = """title: Suspicious PowerShell
id: 195e1b9d-bfc2-4ffa-ab4e-35aef69815f8
logsource:
  category: process_creation
  product: windows
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
"""


def query_of(document: dict[str, object] | None = None, sigma: str | None = None):
    """Return the retrieval query a rule asks the corpus."""
    if sigma is not None:
        parsed = PARSER.parse_as(sigma, RuleFormat.SIGMA)
    else:
        body = document if document is not None else ELASTIC
        parsed = PARSER.registry.for_format(RuleFormat.ELASTIC).parse(
            body, json.dumps(body, default=str)
        )
    mappings = MAPPER.map(EXTRACTOR.extract(parsed))
    return rule_query(
        rule_context_from_parsed(parsed),
        mappings,
        top_k=10,
        ecs_fields=ECS_FIELDS,
    )


# ------------------------------------------------- the identifiers arrive


def test_an_elastic_rule_now_seeds_the_technique_it_states():
    assert query_of().entity_ids == ("T1059", "T1059.001")


def test_an_elastic_rule_without_a_threat_section_seeds_nothing_new():
    document = {key: value for key, value in ELASTIC.items() if key != "threat"}

    assert query_of(document).entity_ids == ()


# ---------------------------------------------------------------- F2


def test_f2_still_admits_only_the_types_that_name_a_corpus_object():
    """The tactic is the case: it is stated, mapped, and still not a seed."""
    assert all(item.startswith("T1") for item in query_of().entity_ids)
    assert "TA0002" not in query_of().entity_ids


def test_f2_still_refuses_a_value_the_corpus_cannot_answer_for():
    document = {**ELASTIC, "query": 'destination.ip : "10.0.0.1" and destination.port : 445'}

    assert query_of(document).entity_ids == ("T1059", "T1059.001")


def test_the_rules_editorial_tags_are_not_seeds():
    mapped = MAPPER.map(
        EXTRACTOR.extract(
            PARSER.registry.for_format(RuleFormat.ELASTIC).parse(
                ELASTIC, json.dumps(ELASTIC)
            )
        )
    )
    labels = [
        item.original.value
        for item in mapped
        if item.canonical_type is CanonicalType.RULE_TAG
    ]

    assert labels == ["Elastic", "Host"]
    assert "Elastic" not in query_of().entity_ids


# ------------------------------------------------------- Phase 5D


def test_the_two_field_vocabularies_are_unchanged_by_the_new_entities():
    query = query_of()

    assert query.canonical_fields == ("process.name", "process.command_line")
    assert query.lexical_fields == ("process.name", "process.command_line")
    assert query.lexical_vocabulary == query.canonical_fields


def test_an_attack_identifier_is_an_entity_and_never_a_field():
    query = query_of()

    assert "T1059" not in query.canonical_fields
    assert "T1059" not in query.lexical_fields
    assert "T1059.001" not in query.lexical_vocabulary


def test_all_identifiers_is_still_the_identifiers_and_the_canonical_fields():
    query = query_of()

    assert query.all_identifiers == (*query.entity_ids, *query.canonical_fields)
    assert query.all_identifiers == (
        "T1059",
        "T1059.001",
        "process.name",
        "process.command_line",
    )


def test_the_canonical_field_order_the_tie_break_reads_is_the_rules_own():
    """Phase 3F reads this order; the new entities must not permute it."""
    document = {
        **ELASTIC,
        "query": 'file.path : "*.dll" and process.name : "rundll32.exe"',
    }

    assert query_of(document).canonical_fields == ("file.path", "process.name")


# ------------------------------------------------------- Sigma is unmoved


def test_a_sigma_rule_asks_exactly_what_it_asked_before():
    query = query_of(sigma=SIGMA)

    assert query.entity_ids == ("T1059.001",)
    assert query.canonical_fields == ("process.executable", "process.command_line")
    assert query.lexical_fields == ("Image", "CommandLine")


def test_the_two_formats_reach_the_same_technique_by_their_own_routes():
    """The point of the change, stated as one comparison.

    Both rules detect encoded PowerShell and both name T1059.001. The Sigma rule
    always seeded it, from its tag list; the Elastic rule now seeds it too, from
    the section it actually writes it in.
    """
    assert "T1059.001" in query_of(sigma=SIGMA).entity_ids
    assert "T1059.001" in query_of().entity_ids
