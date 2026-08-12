"""Stage-15 schema checker.

The structural half of validation: types, enumerations, ranges, required fields
and fields the schema never declared.
"""

from __future__ import annotations

import pytest

from src.core.output_format import ANALYZE_SPEC, ENHANCE_SPEC, GENERATE_SPEC
from src.core.schema import (
    FieldKind,
    FieldSpec,
    ObjectSpec,
    SchemaValidator,
    render_object_spec,
)

SIMPLE = ObjectSpec(
    name="Simple",
    description="A specification exercising every field kind.",
    fields=(
        FieldSpec("name", FieldKind.STRING, "A name."),
        FieldSpec("kind", FieldKind.STRING, "A closed value.", enum=("a", "b")),
        FieldSpec("fixed", FieldKind.STRING, "A fixed value.", const="analyze"),
        FieldSpec("count", FieldKind.INTEGER, "A count.", minimum=0, maximum=10),
        FieldSpec("score", FieldKind.NUMBER, "A score.", minimum=0.0, maximum=1.0),
        FieldSpec("tags", FieldKind.STRING_ARRAY, "Some tags."),
        FieldSpec("meta", FieldKind.STRING_MAP, "String metadata."),
    ),
)


def valid_document():
    return {
        "name": "rule",
        "kind": "a",
        "fixed": "analyze",
        "count": 3,
        "score": 0.5,
        "tags": ["one", "two"],
        "meta": {"k": "v"},
    }


def paths(issues):
    return [issue.path for issue in issues]


def test_valid_document_produces_no_issue():
    assert SchemaValidator(SIMPLE).validate(valid_document()) == ()


def test_missing_field_is_reported_once_per_field():
    document = valid_document()
    del document["name"]
    del document["score"]
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.name", "$.score"]
    assert all("missing" in issue.detail for issue in issues)


def test_undeclared_field_is_rejected():
    document = valid_document()
    document["extra"] = "value"
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.extra"]
    assert "not defined by the schema" in issues[0].detail


def test_wrong_types_are_reported_with_the_json_type_name():
    document = valid_document()
    document["name"] = 5
    document["count"] = "3"
    document["tags"] = "one"
    document["meta"] = []
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.name", "$.count", "$.tags", "$.meta"]
    assert "got integer" in issues[0].detail
    assert "got string" in issues[1].detail


def test_boolean_is_not_accepted_as_a_number():
    document = valid_document()
    document["count"] = True
    document["score"] = False
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.count", "$.score"]
    assert all("boolean" in issue.detail for issue in issues)


def test_null_is_never_a_value():
    document = valid_document()
    document["name"] = None
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.name"]
    assert "got null" in issues[0].detail


def test_value_outside_the_enumeration_is_rejected():
    document = valid_document()
    document["kind"] = "c"
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.kind"]
    assert "is not one of: a, b" in issues[0].detail


def test_fixed_value_must_match_exactly():
    document = valid_document()
    document["fixed"] = "enhance"
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.fixed"]
    assert "expected 'analyze'" in issues[0].detail


def test_numbers_outside_their_range_are_rejected():
    document = valid_document()
    document["count"] = 11
    document["score"] = -0.1
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.count", "$.score"]
    assert "above the maximum 10" in issues[0].detail
    assert "below the minimum 0" in issues[1].detail


def test_strings_must_be_single_line_and_non_empty():
    document = valid_document()
    document["name"] = "first\nsecond"
    document["fixed"] = "analyze"
    document["tags"] = ["ok", "  "]
    issues = SchemaValidator(SIMPLE).validate(document)
    assert paths(issues) == ["$.name", "$.tags[1]"]


def test_nested_arrays_are_addressed_by_index():
    issues = SchemaValidator(ANALYZE_SPEC).validate(
        {
            "operation": "analyze",
            "summary": "s",
            "findings": [{"finding_id": "F1"}],
            "recommendations": [],
            "confidence": 0.5,
            "metadata": {},
            "uncertainties": [],
        }
    )
    assert "$.findings[0].category" in paths(issues)
    assert "$.findings[0].evidence" in paths(issues)


def test_a_non_object_document_is_rejected():
    issues = SchemaValidator(SIMPLE).validate(["not", "an", "object"])
    assert paths(issues) == ["$"]


@pytest.mark.parametrize("spec", [ANALYZE_SPEC, ENHANCE_SPEC, GENERATE_SPEC])
def test_every_operation_schema_renders_deterministically(spec):
    first = render_object_spec(spec)
    assert first == render_object_spec(spec)
    assert "```json" in first
    assert "Field rules:" in first
    for name in spec.field_names():
        assert f"`{name}`" in first


@pytest.mark.parametrize("spec", [ANALYZE_SPEC, ENHANCE_SPEC, GENERATE_SPEC])
def test_every_operation_schema_carries_the_shared_envelope(spec):
    envelope = ("operation", "summary", "findings", "recommendations", "confidence", "metadata")
    assert spec.field_names()[: len(envelope)] == envelope
    assert "uncertainties" in spec.field_names()
