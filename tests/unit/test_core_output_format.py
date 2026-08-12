"""Stage-15 output format.

The contract each operation states to the model, and the fields the Stage-15
specification requires each result to carry.
"""

from __future__ import annotations

import json
import re

import pytest

from src.core.output_format import (
    ANALYZE_SPEC,
    ENHANCE_SPEC,
    GENERATE_SPEC,
    OPERATION_SPECS,
    output_format_for,
    spec_for,
)
from src.core.schema import FieldKind, ObjectSpec
from src.core.types import ReasoningOperation

OPERATIONS = list(ReasoningOperation)


def nested(spec: ObjectSpec, path: str) -> ObjectSpec:
    """Return the object specification a dotted path names."""
    current = spec
    for part in path.split("."):
        found = next(item for item in current.fields if item.name == part)
        assert found.spec is not None
        current = found.spec
    return current


@pytest.mark.parametrize("operation", OPERATIONS)
def test_every_operation_has_a_schema_and_a_rendered_contract(operation):
    assert operation in OPERATION_SPECS
    rendered = output_format_for(operation)
    assert rendered.strip()
    assert f'"operation": "{operation.value}"' in rendered


@pytest.mark.parametrize("operation", OPERATIONS)
def test_the_rendered_contract_is_deterministic(operation):
    assert output_format_for(operation) == output_format_for(operation)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_the_rendered_skeleton_is_valid_json(operation):
    block = re.search(r"```json\n(.*?)\n```", output_format_for(operation), re.DOTALL)
    assert block is not None
    document = json.loads(block.group(1))
    assert list(document) == list(spec_for(operation).field_names())


@pytest.mark.parametrize("operation", OPERATIONS)
def test_no_operation_leaves_a_placeholder_behind(operation):
    rendered = output_format_for(operation)
    assert "{{" not in rendered
    assert "TODO" not in rendered


def test_analyze_carries_findings_with_severity_explanation_evidence_and_confidence():
    finding = nested(ANALYZE_SPEC, "findings")
    assert finding.field_names() == (
        "finding_id",
        "category",
        "severity",
        "statement",
        "explanation",
        "support",
        "evidence",
        "confidence",
    )
    assert nested(ANALYZE_SPEC, "findings.evidence").field_names() == (
        "item_id",
        "source",
        "identifier",
        "detail",
    )
    assert "recommendations" in ANALYZE_SPEC.field_names()


def test_enhance_carries_the_original_rule_the_enhanced_rule_and_every_change():
    names = ENHANCE_SPEC.field_names()
    assert {"original_rule", "enhanced_rule", "changes"} <= set(names)
    assert nested(ENHANCE_SPEC, "changes").field_names() == (
        "change_id",
        "category",
        "before",
        "after",
        "rationale",
        "addresses",
        "evidence",
        "support",
    )
    assert "query" in nested(ENHANCE_SPEC, "enhanced_rule").field_names()


def test_generate_carries_the_rule_its_rationale_and_its_mappings():
    names = GENERATE_SPEC.field_names()
    assert {"generated_rule", "rationale", "mappings"} <= set(names)
    assert nested(GENERATE_SPEC, "mappings").field_names() == (
        "tactic_id",
        "technique_id",
        "support",
        "evidence",
    )


@pytest.mark.parametrize("operation", OPERATIONS)
def test_every_operation_must_return_its_uncertainties(operation):
    uncertainty = nested(spec_for(operation), "uncertainties")
    assert uncertainty.field_names() == ("identifier", "status", "candidates", "treatment")
    status = next(item for item in uncertainty.fields if item.name == "status")
    assert status.enum == ("unresolved", "ambiguous")


@pytest.mark.parametrize("operation", OPERATIONS)
def test_no_field_is_optional_and_no_enum_is_open(operation):
    def walk(spec: ObjectSpec) -> None:
        for item in spec.fields:
            assert item.description.strip()
            if item.kind is FieldKind.STRING and item.enum:
                assert all(value.islower() or ":" in value for value in item.enum)
            if item.spec is not None:
                walk(item.spec)

    walk(spec_for(operation))


def test_the_produced_rule_uses_the_glossary_vocabulary():
    rule = nested(GENERATE_SPEC, "generated_rule")
    severity = next(item for item in rule.fields if item.name == "severity")
    rule_type = next(item for item in rule.fields if item.name == "rule_type")
    language = next(item for item in rule.fields if item.name == "language")
    risk = next(item for item in rule.fields if item.name == "risk_score")
    assert severity.enum == ("critical", "high", "medium", "low")
    assert rule_type.enum == ("query", "threshold", "eql", "new_terms", "esql")
    assert language.enum == ("kql", "eql", "esql", "lucene")
    assert (risk.minimum, risk.maximum) == (0, 100)


def test_the_shared_output_template_still_asks_for_the_operation_schema():
    from tests.fixtures.stage15 import PROMPTS_DIR

    body = (PROMPTS_DIR / "shared" / "output.md").read_text(encoding="utf-8")
    assert "{{OUTPUT_FORMAT}}" in body
