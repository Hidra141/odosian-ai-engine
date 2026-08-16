"""Stage-15 semantic contract.

The fields the Final Contracts need from the reasoning engine, and the fields
they must never ask it for.

Two properties are pinned here. The first is that each operation declares the
semantic judgements that operation actually makes — a score and a false-positive
risk belong to an assessment, not to a rewrite — and that they are typed and
bounded rather than merely present. The second is the negative one, which is
easier to lose: no deterministic or runtime value may reach the prompt. A model
asked for a timestamp will produce one, and a produced timestamp is a fabricated
timestamp.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from src.core.output_format import (
    json_schema_for,
    output_format_for,
    spec_for,
)
from src.core.response_parser import ResponseParser
from src.core.schema import FieldKind, FieldSpec, ObjectSpec, SchemaValidator
from src.core.types import (
    FalsePositiveRisk,
    ReasoningOperation,
)
from tests.fixtures import stage15 as fixtures

OPERATIONS = list(ReasoningOperation)
PARSER = ResponseParser()

RESPONSES = {
    ReasoningOperation.ANALYZE: fixtures.analyze_response,
    ReasoningOperation.ENHANCE: fixtures.enhance_response,
    ReasoningOperation.GENERATE: fixtures.generate_response,
}

CONTEXT_OF = {
    ReasoningOperation.ANALYZE: "analyze",
    ReasoningOperation.ENHANCE: "enhance",
    ReasoningOperation.GENERATE: "generate",
}


def walk(spec: ObjectSpec, prefix: str = "") -> Iterator[tuple[str, FieldSpec]]:
    """Yield every field of a spec and of every spec nested inside it."""
    for item in spec.fields:
        path = f"{prefix}{item.name}"
        yield path, item
        if item.spec is not None:
            yield from walk(item.spec, f"{path}.")


def field_at(operation: ReasoningOperation, path: str) -> FieldSpec:
    """Return one declared field of an operation, by dotted path."""
    for name, item in walk(spec_for(operation)):
        if name == path:
            return item
    raise AssertionError(f"{operation.value} declares no field {path!r}")


def payload_for(operation: ReasoningOperation):
    """Return a valid response body and the package that produced it."""
    from src.context.types import ContextOperation

    package = fixtures.context_package(ContextOperation(CONTEXT_OF[operation]))
    return RESPONSES[operation](package), package


def issues(operation: ReasoningOperation, document) -> tuple[str, ...]:
    """Return the schema faults of a document, as strings."""
    return tuple(str(issue) for issue in SchemaValidator(spec_for(operation)).validate(document))


# 1-3 — each operation declares the judgements it actually makes


def test_analyze_declares_its_assessment_fields():
    names = set(spec_for(ReasoningOperation.ANALYZE).field_names())
    assert {"score", "fp_risk", "strengths", "evasion_risks", "mappings"} <= names


def test_enhance_declares_no_assessment_fields():
    """Enhance rewrites; it does not score. The Final Contract fixes its score at 0."""
    names = set(spec_for(ReasoningOperation.ENHANCE).field_names())
    assert not {"score", "fp_risk", "strengths", "evasion_risks"} & names
    assert {"original_rule", "enhanced_rule", "changes"} <= names


def test_generate_declares_a_self_assessed_score_only():
    names = set(spec_for(ReasoningOperation.GENERATE).field_names())
    assert "score" in names
    assert not {"fp_risk", "strengths", "evasion_risks"} & names
    rule = field_at(ReasoningOperation.GENERATE, "generated_rule")
    assert rule.spec is not None
    assert "tags" in rule.spec.field_names()


# 4 — the new fields are typed, not merely present


def test_the_new_fields_carry_their_intended_kinds():
    analyze = ReasoningOperation.ANALYZE
    assert field_at(analyze, "score").kind is FieldKind.INTEGER
    assert field_at(analyze, "fp_risk").kind is FieldKind.STRING
    assert field_at(analyze, "strengths").kind is FieldKind.STRING_ARRAY
    assert field_at(analyze, "evasion_risks").kind is FieldKind.OBJECT_ARRAY
    assert field_at(analyze, "weaknesses").kind is FieldKind.STRING_ARRAY
    assert field_at(analyze, "mappings").kind is FieldKind.OBJECT_ARRAY
    assert field_at(ReasoningOperation.GENERATE, "score").kind is FieldKind.INTEGER
    rule = field_at(ReasoningOperation.GENERATE, "generated_rule.tags")
    assert rule.kind is FieldKind.STRING_ARRAY


# 5 — score is bounded


@pytest.mark.parametrize("value", [-1, 101, 140])
def test_a_score_outside_its_range_is_rejected(value):
    document, _ = payload_for(ReasoningOperation.ANALYZE)
    document["score"] = value
    assert any("score" in issue for issue in issues(ReasoningOperation.ANALYZE, document))


def test_a_score_inside_its_range_is_accepted():
    document, _ = payload_for(ReasoningOperation.ANALYZE)
    for value in (0, 50, 100):
        document["score"] = value
        assert issues(ReasoningOperation.ANALYZE, document) == ()


def test_the_score_bounds_are_declared_as_zero_to_one_hundred():
    spec = field_at(ReasoningOperation.ANALYZE, "score")
    assert (spec.minimum, spec.maximum) == (0, 100)


# 6 — fp_risk is a closed enumeration


def test_fp_risk_accepts_only_the_approved_values():
    spec = field_at(ReasoningOperation.ANALYZE, "fp_risk")
    assert spec.enum == ("critical", "high", "medium", "low")
    assert set(spec.enum) == {member.value for member in FalsePositiveRisk}


@pytest.mark.parametrize("value", ["extreme", "LOW", "unknown", ""])
def test_an_unapproved_fp_risk_is_rejected(value):
    document, _ = payload_for(ReasoningOperation.ANALYZE)
    document["fp_risk"] = value
    assert any("fp_risk" in issue for issue in issues(ReasoningOperation.ANALYZE, document))


# 7 — mapping confidence is bounded at 0.0..1.0


@pytest.mark.parametrize("value", [-0.1, 1.5, 100])
def test_a_mapping_confidence_outside_zero_to_one_is_rejected(value):
    document, _ = payload_for(ReasoningOperation.ANALYZE)
    document["mappings"][0]["confidence"] = value
    assert any("confidence" in issue for issue in issues(ReasoningOperation.ANALYZE, document))


def test_mapping_confidence_is_declared_separately_from_the_envelope():
    """The mapping's own confidence is about the mapping, not about the answer."""
    mapping = field_at(ReasoningOperation.ANALYZE, "mappings.confidence")
    envelope = field_at(ReasoningOperation.ANALYZE, "confidence")
    assert (mapping.minimum, mapping.maximum) == (0.0, 1.0)
    assert mapping.description != envelope.description
    assert "this specific mapping" in mapping.description


# 8 — MITRE names are represented, everywhere a mapping is


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
def test_every_mapping_shape_carries_names_beside_identifiers(operation):
    shapes = [
        (name, item)
        for name, item in walk(spec_for(operation))
        if item.spec is not None and "tactic_id" in item.spec.field_names()
    ]
    assert shapes, f"{operation.value} declares no ATT&CK mapping"
    for _, item in shapes:
        assert item.spec is not None
        names = item.spec.field_names()
        assert {"tactic_name", "technique_name", "confidence"} <= set(names)


def test_a_name_may_be_empty_but_a_technique_id_may_not():
    """An unnamed identifier is a real answer; an absent identifier is not."""
    assert field_at(ReasoningOperation.ANALYZE, "mappings.tactic_name").allow_empty
    assert field_at(ReasoningOperation.ANALYZE, "mappings.technique_name").allow_empty
    assert not field_at(ReasoningOperation.ANALYZE, "mappings.technique_id").allow_empty


# 9-11 — nothing that already worked stopped working


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
def test_citations_are_still_declared_on_every_claim(operation):
    citing = [
        name
        for name, item in walk(spec_for(operation))
        if item.spec is not None and "item_id" in item.spec.field_names()
    ]
    assert "findings.evidence" in citing


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
def test_uncertainty_is_still_declared_on_every_operation(operation):
    spec = field_at(operation, "uncertainties")
    assert spec.spec is not None
    assert spec.spec.field_names() == ("identifier", "status", "candidates", "treatment")
    assert field_at(operation, "uncertainties.status").enum == ("unresolved", "ambiguous")


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
def test_ambiguous_identifiers_still_carry_every_candidate(operation):
    document, _ = payload_for(operation)
    carried = {entry["identifier"]: entry for entry in document["uncertainties"]}
    assert carried["M1013"]["status"] == "ambiguous"
    assert carried["M1013"]["candidates"] == ["enterprise:M1013", "mobile:M1013"]
    assert carried["T1562"]["status"] == "unresolved"
    assert issues(operation, document) == ()


# 12-15 — the model is never asked for a deterministic or runtime value

FORBIDDEN = (
    "rating",
    "interval",
    "from_time",
    "fromTime",
    "max_signals",
    "maxSignals",
    "user_id",
    "userId",
    "created_at",
    "createdAt",
    "latency_ms",
    "latencyMs",
)


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
@pytest.mark.parametrize("forbidden", FORBIDDEN)
def test_no_runtime_or_derived_field_is_declared(operation, forbidden):
    declared = {name.rsplit(".", 1)[-1] for name, _ in walk(spec_for(operation))}
    assert forbidden not in declared


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
@pytest.mark.parametrize("forbidden", FORBIDDEN)
def test_no_runtime_or_derived_field_reaches_the_prompt(operation, forbidden):
    """Not merely undeclared — the rendered OUTPUT_FORMAT must not name it either."""
    rendered = output_format_for(operation)
    assert not re.search(rf"\b{re.escape(forbidden)}\b", rendered)


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
@pytest.mark.parametrize("forbidden", FORBIDDEN)
def test_no_runtime_or_derived_field_reaches_the_json_schema(operation, forbidden):
    assert forbidden not in str(json_schema_for(operation))


# 16 — no realistic identifier is left in the contract to be copied

_REAL_IDENTIFIER = re.compile(r"\b(?:TA\d{4}|T\d{4}(?:\.\d{3})?|M\d{4}|S\d{4}|G\d{4})\b")


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
def test_no_schema_description_shows_a_real_looking_identifier(operation):
    """The live enhance call invented TA0002, which the schema had shown it."""
    offenders = [
        (name, _REAL_IDENTIFIER.findall(item.description))
        for name, item in walk(spec_for(operation))
        if _REAL_IDENTIFIER.search(item.description)
    ]
    assert offenders == []


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
def test_the_rendered_prompt_shows_no_real_looking_identifier(operation):
    assert _REAL_IDENTIFIER.findall(output_format_for(operation)) == []


def test_identifier_guidance_uses_neutral_placeholders_instead():
    description = field_at(ReasoningOperation.ANALYZE, "mappings.technique_id").description
    assert "<TECHNIQUE_ID>" in description


# 17 — strict parsing still holds, and the new fields survive it


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda o: o.value)
def test_a_valid_response_still_parses_into_a_typed_result(operation):
    document, _ = payload_for(operation)
    response = fixtures.response_of(fixtures.body_of(document))
    result = PARSER.parse(operation, response)
    assert result.operation is operation


def test_the_analyze_judgements_survive_into_the_typed_result():
    document, _ = payload_for(ReasoningOperation.ANALYZE)
    result = PARSER.parse(
        ReasoningOperation.ANALYZE, fixtures.response_of(fixtures.body_of(document))
    )
    assert result.score == document["score"]
    assert result.fp_risk is FalsePositiveRisk(document["fp_risk"])
    assert result.strengths == tuple(document["strengths"])
    assert [r.technique for r in result.evasion_risks] == [
        e["technique"] for e in document["evasion_risks"]
    ]
    assert result.weaknesses == tuple(document["weaknesses"])
    assert result.mappings[0].technique_id == "T1059.001"
    assert result.mappings[0].confidence == 0.75


def test_the_generated_rule_tags_and_mapping_names_survive_into_the_typed_result():
    document, _ = payload_for(ReasoningOperation.GENERATE)
    result = PARSER.parse(
        ReasoningOperation.GENERATE, fixtures.response_of(fixtures.body_of(document))
    )
    assert result.score == document["score"]
    assert result.generated_rule.tags == ("Windows", "PowerShell")
    assert result.generated_rule.mitre[0].confidence == 0.8
    assert result.generated_rule.mitre[0].technique_name == ""


def test_an_analyze_mapping_citation_is_reachable_from_the_result():
    """The new mappings carry evidence, and that evidence must remain addressable."""
    document, package = payload_for(ReasoningOperation.ANALYZE)
    result = PARSER.parse(
        ReasoningOperation.ANALYZE, fixtures.response_of(fixtures.body_of(document))
    )
    cited = set(result.cited_item_ids())
    assert cited <= {item.item_id for item in package.items}
    assert result.mappings[0].evidence[0].item_id in cited


def test_a_recommendation_code_snippet_survives_into_the_typed_result():
    document, _ = payload_for(ReasoningOperation.ANALYZE)
    result = PARSER.parse(
        ReasoningOperation.ANALYZE, fixtures.response_of(fixtures.body_of(document))
    )
    assert result.recommendations[0].code_snippet == (
        document["recommendations"][0]["code_snippet"]
    )


# Phase C — contract compatibility fields


def test_analyze_declares_weaknesses_separately_from_findings():
    """The contract carries both; one is not a restatement of the other."""
    names = set(spec_for(ReasoningOperation.ANALYZE).field_names())
    assert {"weaknesses", "findings"} <= names
    described = field_at(ReasoningOperation.ANALYZE, "weaknesses").description
    assert "not a restatement of the findings" in described


def test_evasion_risks_carry_the_three_parts_the_contract_needs():
    spec = field_at(ReasoningOperation.ANALYZE, "evasion_risks")
    assert spec.kind is FieldKind.OBJECT_ARRAY
    assert spec.spec is not None
    assert spec.spec.field_names() == ("technique", "description", "mitigation")


def test_every_mapping_carries_the_parent_technique_fields():
    for operation in OPERATIONS:
        shapes = [
            item
            for _, item in walk(spec_for(operation))
            if item.spec is not None and "technique_id" in item.spec.field_names()
        ]
        assert shapes
        for item in shapes:
            assert item.spec is not None
            assert {"parent_technique_id", "parent_technique_name"} <= set(
                item.spec.field_names()
            )


def test_a_parent_technique_may_be_empty_and_is_never_truncated_from_a_child():
    spec = field_at(ReasoningOperation.ANALYZE, "mappings.parent_technique_id")
    assert spec.allow_empty
    assert "never derive a parent by truncating" in spec.description.lower()


def test_generate_declares_notes_as_forward_looking_not_a_summary():
    spec = field_at(ReasoningOperation.GENERATE, "notes")
    assert spec.kind is FieldKind.STRING
    assert spec.allow_empty
    assert "not a summary of what you already wrote" in spec.description


def test_the_new_compatibility_fields_survive_into_the_typed_results():
    document, _ = payload_for(ReasoningOperation.ANALYZE)
    analyze = PARSER.parse(
        ReasoningOperation.ANALYZE, fixtures.response_of(fixtures.body_of(document))
    )
    assert analyze.weaknesses == tuple(document["weaknesses"])
    assert analyze.evasion_risks[0].technique == document["evasion_risks"][0]["technique"]
    assert analyze.evasion_risks[0].mitigation == document["evasion_risks"][0]["mitigation"]
    assert analyze.mappings[0].parent_technique_id == ""

    body, _ = payload_for(ReasoningOperation.GENERATE)
    generate = PARSER.parse(
        ReasoningOperation.GENERATE, fixtures.response_of(fixtures.body_of(body))
    )
    assert generate.notes == body["notes"]


def test_no_runtime_field_crept_in_with_the_compatibility_extension():
    for operation in OPERATIONS:
        declared = {name.rsplit(".", 1)[-1] for name, _ in walk(spec_for(operation))}
        assert not declared & {"rating", "userId", "createdAt", "latencyMs", "references"}
