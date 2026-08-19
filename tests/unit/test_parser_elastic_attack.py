"""Reading the ATT&CK references an Elastic rule states, and saying where.

Sigma writes its ATT&CK identifiers among its tags, so every stage after the
parser learned to look in the tag list. Elastic writes them in a section of its
own and puts editorial labels in its tags — ``Elastic``, ``Host``, ``Windows``
— and across the 2,145 bundled Elastic rules not one states an ATT&CK
identifier among them. So an Elastic rule reached retrieval with no technique
to ask about, and the graph, which is keyed by exactly those identifiers, had
nothing to walk from.

The identifiers were never lost: the whole document survives on
:attr:`~src.parser.models.ParsedRule.raw`. They were simply never read, because
the model had no field that meant *the ATT&CK the rule states* and ``raw`` is
kept for a reader to go back to, not for a stage to mine.

Two things are being checked here, and the second matters as much as the first.
The identifiers must arrive — techniques and the sub-techniques nested beneath
them, once each, in the order the rule reads. And they must arrive **as what
they are**: a reference read from ``threat`` is reported as coming from
``threat``, never folded into the tag list, because a rule that says
``tags: [Elastic, Host]`` did not tag itself ``T1059.001`` and a package that
claims otherwise describes a rule its author did not write.
"""

from __future__ import annotations

import json

from src.entities.extractor import EntityExtractor
from src.entities.types import EntityType, RuleSection
from src.mapping.entity_mapper import EntityMapper
from src.mapping.types import CanonicalType
from src.parser.models import AttackReference
from src.parser.parser import RuleParser
from src.parser.types import RuleFormat

PARSER = RuleParser()
EXTRACTOR = EntityExtractor()
MAPPER = EntityMapper()

BASE = {
    "name": "Suspicious Interpreter",
    "rule_id": "8a1f2c34-0000-4c11-9f00-2b7a5c9e1234",
    "query": 'process.name : "powershell.exe"',
    "language": "kuery",
    "type": "query",
    "index": ["logs-endpoint.events.process-*"],
    "tags": ["Elastic", "Host"],
}


def elastic(**extra: object):
    """Return the rule a document with these additions parses to."""
    document = {**BASE, **extra}
    return PARSER.registry.for_format(RuleFormat.ELASTIC).parse(
        document, json.dumps(document, default=str)
    )


def threat(*entries: object) -> dict[str, object]:
    """Return a document fragment stating a threat section."""
    return {"threat": list(entries)}


def technique(identifier: str, *subs: str) -> dict[str, object]:
    """Return one technique entry, with any sub-techniques beneath it."""
    entry: dict[str, object] = {"id": identifier, "name": identifier}
    if subs:
        entry["subtechnique"] = [{"id": sub, "name": sub} for sub in subs]
    return entry


def entry(tactic: str, *techniques: object) -> dict[str, object]:
    """Return one threat entry: a tactic and the techniques serving it."""
    return {
        "framework": "MITRE ATT&CK",
        "tactic": {"id": tactic, "name": tactic},
        "technique": list(techniques),
    }


def identifiers(rule) -> tuple[str, ...]:
    """Return the ATT&CK identifiers a rule states, in order."""
    return tuple(item.identifier for item in rule.attack_references)


def tag_entities(rule):
    """Return the tag entities a rule produces, in extraction order."""
    return tuple(
        item
        for item in EXTRACTOR.extract(rule)
        if item.entity_type is EntityType.TAG
    )


def attack_ids(rule) -> tuple[str, ...]:
    """Return the ATT&CK identifiers the mapping layer resolves, in order."""
    mapped = MAPPER.map(EXTRACTOR.extract(rule))
    return tuple(
        item.canonical_id
        for item in mapped.resolved
        if item.canonical_id and item.canonical_type.value.startswith("attack")
    )


# ------------------------------------------------------- 1-2. what arrives


def test_a_technique_is_read_from_the_threat_section():
    rule = elastic(**threat(entry("TA0002", technique("T1059"))))

    assert identifiers(rule) == ("T1059",)
    assert attack_ids(rule) == ("T1059",)


def test_a_sub_technique_nested_under_its_technique_is_read_too():
    """The case the knowledge base could not have shown.

    The bundled corpus's own metadata flattens sub-techniques away entirely —
    it states none — while the rules themselves name 282 distinct ones. Reading
    them requires the document, which is why they are read from it.
    """
    rule = elastic(**threat(entry("TA0002", technique("T1059", "T1059.001"))))

    assert identifiers(rule) == ("T1059", "T1059.001")
    assert attack_ids(rule) == ("T1059", "T1059.001")


def test_several_sub_techniques_all_arrive():
    rule = elastic(
        **threat(entry("TA0002", technique("T1059", "T1059.001", "T1059.003")))
    )

    assert identifiers(rule) == ("T1059", "T1059.001", "T1059.003")


# ------------------------------------------- 3-6. several entries, in order


def test_every_threat_entry_is_read():
    rule = elastic(
        **threat(
            entry("TA0002", technique("T1059")),
            entry("TA0005", technique("T1218")),
        )
    )

    assert identifiers(rule) == ("T1059", "T1218")


def test_a_technique_serving_two_tactics_is_stated_once():
    """Elastic writes one entry per tactic, so this is 492 rules of 2,145."""
    rule = elastic(
        **threat(
            entry("TA0002", technique("T1059")),
            entry("TA0005", technique("T1059")),
        )
    )

    assert identifiers(rule) == ("T1059",)


def test_a_repeat_keeps_the_place_the_rule_first_stated_it():
    rule = elastic(
        **threat(
            entry("TA0002", technique("T1218")),
            entry("TA0005", technique("T1218")),
        )
    )

    assert rule.attack_references == (
        AttackReference("T1218", "threat[0].technique[0]"),
    )


def test_the_order_is_the_order_the_rule_reads_in():
    rule = elastic(
        **threat(
            entry("TA0002", technique("T1059", "T1059.001"), technique("T1106")),
            entry("TA0005", technique("T1218", "T1218.011")),
        )
    )

    assert identifiers(rule) == (
        "T1059",
        "T1059.001",
        "T1106",
        "T1218",
        "T1218.011",
    )


# ------------------------------------------------------ 7. tactics excluded


def test_a_tactic_is_not_read_as_an_attack_reference():
    """Deferred deliberately, not overlooked.

    A tactic identifier names the highest-degree nodes in the graph — mean
    degree 324 against a technique's 17 — so seeding one is a different
    question from seeding a technique, and it is answered separately.
    """
    rule = elastic(**threat(entry("TA0002", technique("T1059"))))

    assert "TA0002" not in identifiers(rule)
    assert all(not item.startswith("TA") for item in identifiers(rule))


def test_a_threat_entry_stating_only_a_tactic_states_nothing_here():
    rule = elastic(**threat({"tactic": {"id": "TA0002", "name": "Execution"}}))

    assert rule.attack_references == ()


def test_no_tactic_identifier_reaches_the_mapping_layer_from_threat():
    rule = elastic(**threat(entry("TA0002", technique("T1059"))))
    mapped = MAPPER.map(EXTRACTOR.extract(rule))
    tactics = [
        item
        for item in mapped
        if item.canonical_type is CanonicalType.ATTACK_TACTIC_REFERENCE
    ]

    assert tactics == []


# --------------------------------------------------- 8, 12. the tags stay


def test_the_rules_own_tags_are_untouched():
    rule = elastic(**threat(entry("TA0002", technique("T1059"))))

    assert rule.tags == ("Elastic", "Host")


def test_the_tag_entities_keep_the_places_they_always_had():
    rule = elastic(**threat(entry("TA0002", technique("T1059"))))
    tags = [item for item in tag_entities(rule) if item.source_field == "tags"]

    assert [(item.value, item.location) for item in tags] == [
        ("Elastic", "tags[0]"),
        ("Host", "tags[1]"),
    ]


def test_an_editorial_tag_is_still_only_a_tag():
    rule = elastic(**threat(entry("TA0002", technique("T1059"))))
    mapped = MAPPER.map(EXTRACTOR.extract(rule))
    labels = [
        item.original.value
        for item in mapped
        if item.canonical_type is CanonicalType.RULE_TAG
    ]

    assert labels == ["Elastic", "Host"]


# ------------------------------------------------ 11-12. truthful provenance


def test_a_reference_says_it_came_from_the_threat_section():
    rule = elastic(**threat(entry("TA0002", technique("T1059"))))
    derived = [item for item in tag_entities(rule) if item.value == "T1059"]

    assert [item.source_field for item in derived] == ["threat"]


def test_no_derived_reference_is_reported_as_a_tag():
    rule = elastic(
        **threat(entry("TA0002", technique("T1059", "T1059.001")))
    )
    claimed = [
        item.value for item in tag_entities(rule) if item.source_field == "tags"
    ]

    assert claimed == ["Elastic", "Host"]


def test_the_location_names_the_position_the_rule_wrote_it_at():
    rule = elastic(
        **threat(
            entry("TA0002", technique("T1106")),
            entry("TA0005", technique("T1218", "T1218.011")),
        )
    )

    assert rule.attack_references == (
        AttackReference("T1106", "threat[0].technique[0]"),
        AttackReference("T1218", "threat[1].technique[0]"),
        AttackReference("T1218.011", "threat[1].technique[0].subtechnique[0]"),
    )


def test_the_entity_carries_that_same_location():
    rule = elastic(**threat(entry("TA0002", technique("T1059", "T1059.001"))))
    derived = [item for item in tag_entities(rule) if item.source_field == "threat"]

    assert [item.location for item in derived] == [
        "threat[0].technique[0]",
        "threat[0].technique[0].subtechnique[0]",
    ]
    assert {item.section for item in derived} == {RuleSection.TAGS}


# ------------------------------------------------------- 9-10. malformed


def test_a_rule_stating_no_threat_section_is_unchanged():
    rule = elastic()

    assert rule.attack_references == ()
    assert rule.tags == ("Elastic", "Host")
    assert [item.value for item in tag_entities(rule)] == ["Elastic", "Host"]


def test_every_malformed_threat_shape_states_nothing_and_raises_nothing():
    """The shapes a rule can arrive in when its threat section is not one.

    None of these is a parse failure. A rule whose ``threat`` is null said
    nothing about ATT&CK; a rule whose ``threat`` is a string said something
    this parser cannot read. Both are rules that state no identifier here, and
    neither is a reason to refuse the rule.
    """
    for malformed in (
        None,
        [],
        "MITRE ATT&CK",
        [None, 5],
        [{"framework": "MITRE ATT&CK"}],
        [{"technique": "T1059"}],
        [{"technique": [{"name": "no id"}]}],
        [{"technique": [{"id": 1059}]}],
        [{"technique": [{"id": "   "}]}],
        [{"technique": [None, 7]}],
        {"technique": [{"id": "T1059"}]},
    ):
        rule = elastic(threat=malformed)

        assert rule.attack_references == (), malformed
        assert rule.tags == ("Elastic", "Host"), malformed
        assert attack_ids(rule) == (), malformed


def test_a_malformed_sub_technique_does_not_discard_its_technique():
    """Half a statement is still a statement."""
    for broken in ("T1059.001", [None], [7], {"id": "T1059.001"}):
        rule = elastic(**threat({"technique": [{"id": "T1059", "subtechnique": broken}]}))

        assert identifiers(rule) == ("T1059",), broken


def test_a_technique_the_mapper_cannot_read_is_not_made_into_one():
    """The parser reports what the rule states; Stage-10 owns the syntax."""
    rule = elastic(**threat({"technique": [{"id": "not-an-identifier"}]}))
    mapped = MAPPER.map(EXTRACTOR.extract(rule))
    kinds = {
        item.canonical_type
        for item in mapped
        if item.original.value == "not-an-identifier"
    }

    assert identifiers(rule) == ("not-an-identifier",)
    assert kinds == {CanonicalType.RULE_TAG}
    assert attack_ids(rule) == ()


# ------------------------------------------------------- 13. Sigma is still Sigma


SIGMA_RULE = """title: Suspicious PowerShell
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


def test_a_sigma_rule_states_no_threat_section_and_keeps_its_tags():
    rule = PARSER.parse_as(SIGMA_RULE, RuleFormat.SIGMA)

    assert rule.attack_references == ()
    assert rule.tags == ("attack.execution", "attack.t1059.001")


def test_sigma_still_reaches_its_technique_through_its_tags():
    rule = PARSER.parse_as(SIGMA_RULE, RuleFormat.SIGMA)

    assert attack_ids(rule) == ("T1059.001",)


def test_sigma_tag_entities_are_unchanged():
    rule = PARSER.parse_as(SIGMA_RULE, RuleFormat.SIGMA)

    assert [
        (item.value, item.source_field, item.location) for item in tag_entities(rule)
    ] == [
        ("attack.execution", "tags", "tags[0]"),
        ("attack.t1059.001", "tags", "tags[1]"),
    ]
