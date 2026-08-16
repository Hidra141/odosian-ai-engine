"""Stage-17 end to end.

A real Sigma rule through the real Stage-08, Stage-09, Stage-10 and Stage-14
objects, into the Stage-15 engine over a fake provider, out through the Stage-16
boundary, and into the operation's contract document.

Retrieval is supplied as a fixture rather than run, so no test here reads a
dataset, and no provider is called. Everything else on the path is the shipped
code — which is the point: the contract has to hold for the result the pipeline
actually produces, not for one written to suit the formatter.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from src.context.context_builder import ContextBuilder
from src.context.types import ContextOperation
from src.context.validation import ContextValidator
from src.core.models import AnalyzeRequest, EnhanceRequest, GenerateRequest
from src.entities.extractor import EntityExtractor
from src.formatter import RuntimeContext, format_result
from src.mapping.entity_mapper import EntityMapper
from src.parser.parser import RuleParser
from src.validation import ValidationEngine
from tests.fixtures import stage15 as fixtures

VALIDATOR = ValidationEngine()

RUNTIME = RuntimeContext(
    id="80ea7075-5585-4f0f-914a-f643b4c8c3f2",
    user_id="8a9ffc32-8495-4a25-a616-362d90f35dcc",
    created_at="2026-07-24T09:15:30.000Z",
    latency_ms=9400,
    rule_id="1bdc1065-5bd4-4dd6-a6df-c111d643ff90",
    input_query=fixtures.RULE_QUERY,
)

CALLS = {
    ContextOperation.ANALYZE: (fixtures.analyze_response, "analyze", AnalyzeRequest),
    ContextOperation.ENHANCE: (fixtures.enhance_response, "enhance", EnhanceRequest),
    ContextOperation.GENERATE: (fixtures.generate_response, "generate", GenerateRequest),
}


def pipeline(operation: ContextOperation):
    """Run the frozen stages, Stage-15 and Stage-16, and return the accepted result."""
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    entities = EntityExtractor().extract(parsed)
    mappings = EntityMapper().map(entities)
    package = ContextBuilder().build(
        operation,
        rule=parsed,
        entities=entities,
        mappings=mappings,
        retrieval=fixtures.retrieval_result(),
    )
    ContextValidator().validate(package).raise_if_invalid()
    response_of, call, request_of = CALLS[operation]
    engine = fixtures.engine_of(fixtures.provider_returning([response_of(package)]))
    result = getattr(engine, call)(request_of(package=package))
    accepted = VALIDATOR.validate_or_raise(result, package)
    return accepted, package


@pytest.mark.parametrize("operation", list(CALLS), ids=lambda o: o.value)
def test_the_whole_pipeline_ends_in_a_contract_document(operation):
    accepted, _ = pipeline(operation)
    document = format_result(accepted, RUNTIME)
    assert document["analysis"]["analysisType"] == operation.value


@pytest.mark.parametrize("operation", list(CALLS), ids=lambda o: o.value)
def test_every_document_is_json_serialisable_as_produced(operation):
    """No tuple, enum or dataclass may survive into the document."""
    accepted, _ = pipeline(operation)
    encoded = json.dumps(format_result(accepted, RUNTIME))
    assert json.loads(encoded) == format_result(accepted, RUNTIME)


def test_the_analyze_document_carries_the_derived_grade():
    accepted, _ = pipeline(ContextOperation.ANALYZE)
    analysis = format_result(accepted, RUNTIME)["analysis"]
    assert analysis["score"] == 62
    assert analysis["rating"] == "C"
    assert analysis["fpRisk"] == "medium"
    assert analysis["weaknesses"]
    assert analysis["evasionRisks"][0]["mitigation"]


def test_the_enhance_document_carries_the_sentinels_and_a_changelog():
    accepted, _ = pipeline(ContextOperation.ENHANCE)
    analysis = format_result(accepted, RUNTIME)["analysis"]
    assert (analysis["score"], analysis["rating"]) == (0, "")
    assert analysis["changelog"][0]["change"].startswith(("Added ", "Removed ", "Changed "))
    assert analysis["newMitreMappings"][0]["techniqueId"] == "T1059.001"


def test_the_generate_document_carries_the_rule_and_its_schedule():
    accepted, _ = pipeline(ContextOperation.GENERATE)
    analysis = format_result(accepted, RUNTIME)["analysis"]
    assert analysis["language"] == "kuery"
    assert analysis["tags"] == ["Windows", "PowerShell"]
    assert (analysis["interval"], analysis["fromTime"], analysis["maxSignals"]) == (
        "5m",
        "now-6m",
        100,
    )
    assert analysis["notes"]


def test_a_mapping_without_a_supplied_parent_reports_null_sub_technique():
    """The fixture supplies no parent, so the contract's null is what belongs here."""
    accepted, _ = pipeline(ContextOperation.ANALYZE)
    mapping = format_result(accepted, RUNTIME)["analysis"]["mitreMappings"][0]
    assert mapping["techniqueId"] == "T1059.001"
    assert mapping["subTechniqueId"] is None
    assert mapping["subTechniqueName"] is None
    assert mapping["confidence"] == 75


def test_no_uncertainty_or_citation_leaks_into_the_document():
    """The contracts carry neither; Stage-16 keeps them, the document does not."""
    for operation in CALLS:
        accepted, _ = pipeline(operation)
        encoded = json.dumps(format_result(accepted, RUNTIME))
        assert "uncertaint" not in encoded.lower()
        assert "item_id" not in encoded
        assert accepted.uncertainties


def test_formatting_leaves_the_accepted_result_untouched():
    accepted, _ = pipeline(ContextOperation.ANALYZE)
    before = dataclasses.replace(accepted)
    format_result(accepted, RUNTIME)
    assert accepted == before
