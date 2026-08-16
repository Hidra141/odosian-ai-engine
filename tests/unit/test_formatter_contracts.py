"""Stage-17 against the three contracts.

Each formatter is checked against the field set its contract states, not merely
for serialising without error. The three key sets below are transcribed from
``01-analyze.jsonc``, ``03-enhance.jsonc`` and ``05-generate.jsonc``, in the
order those files state them.

The leakage cases matter most. Three documents built from one engine invite a
field wandering from the operation that owns it into one that does not, and a
stray ``rating`` on a generation or a ``weaknesses`` on a rewrite would be
accepted by any test that only looked for the fields it expected.
"""

from __future__ import annotations

import dataclasses

import pytest

from src.context.types import ContextOperation
from src.core.models import AnalyzeRequest, EnhanceRequest, GenerateRequest
from src.core.types import ReasoningOperation
from src.formatter import (
    OperationMismatchError,
    RuntimeContext,
    format_analyze,
    format_enhance,
    format_generate,
    format_result,
)
from tests.fixtures import stage15 as fixtures

RUNTIME = RuntimeContext(
    id="896763ce-c154-4e17-bcbb-2cbb99074cc1",
    user_id="8a9ffc32-8495-4a25-a616-362d90f35dcc",
    created_at="2026-07-24T09:12:03.000Z",
    latency_ms=8120,
    rule_id="1bdc1065-5bd4-4dd6-a6df-c111d643ff90",
    input_query="process.name:\"powershell.exe\"",
)

SAVED = dataclasses.replace(
    RUNTIME,
    saved_rule_id="9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
    saved_rule_title="AWS IAM Policy Attached with Full Administrative Access",
)

ANALYZE_KEYS = [
    "id", "ruleId", "analysisType", "inputQuery", "outputQuery", "score", "rating",
    "fpRisk", "feedback", "strengths", "weaknesses", "findings", "suggestions",
    "evasionRisks", "mitreMappings", "modelUsed", "tokensUsed", "latencyMs",
    "userId", "createdAt",
]

ENHANCE_KEYS = [
    "id", "ruleId", "analysisType", "inputQuery", "score", "rating", "modelUsed",
    "tokensUsed", "latencyMs", "userId", "createdAt", "enhancedQuery", "changelog",
    "newSeverity", "newRiskScore", "investigationGuide", "falsePositives",
    "references", "indexPatterns", "newMitreMappings", "enhancedTitle",
    "enhancedDescription",
]

GENERATE_KEYS = [
    "id", "analysisType", "modelUsed", "tokensUsed", "latencyMs", "userId",
    "createdAt", "title", "description", "query", "language", "ruleType",
    "severity", "riskScore", "tags", "indexPatterns", "interval", "fromTime",
    "maxSignals", "investigationGuide", "falsePositives", "references",
    "mitreMappings", "score", "notes",
]

BUILDERS = {
    ReasoningOperation.ANALYZE: (
        ContextOperation.ANALYZE, fixtures.analyze_response, "analyze", AnalyzeRequest
    ),
    ReasoningOperation.ENHANCE: (
        ContextOperation.ENHANCE, fixtures.enhance_response, "enhance", EnhanceRequest
    ),
    ReasoningOperation.GENERATE: (
        ContextOperation.GENERATE, fixtures.generate_response, "generate", GenerateRequest
    ),
}


def result_for(operation: ReasoningOperation):
    """Return a real Stage-15 result and the package that produced it."""
    context_operation, response_of, call, request_of = BUILDERS[operation]
    package = fixtures.context_package(context_operation)
    engine = fixtures.engine_of(fixtures.provider_returning([response_of(package)]))
    return getattr(engine, call)(request_of(package=package)), package


# A — ANALYZE


def test_analyze_produces_exactly_its_contract_field_set():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    document = format_analyze(result, RUNTIME)
    assert list(document) == ["analysis"]
    assert list(document["analysis"]) == ANALYZE_KEYS


def test_analyze_carries_the_values_the_contract_fixes():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    analysis = format_analyze(result, RUNTIME)["analysis"]
    assert analysis["analysisType"] == "analyze"
    assert analysis["outputQuery"] == ""
    assert analysis["score"] == result.score
    assert analysis["rating"] == "C"
    assert analysis["fpRisk"] in {"low", "medium", "high"}
    assert analysis["feedback"] == result.summary


def test_analyze_rating_is_derived_and_a_model_rating_could_not_override_it():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    for score, expected in ((100, "A+"), (84, "B"), (29, "F")):
        analysis = format_analyze(dataclasses.replace(result, score=score), RUNTIME)
        assert analysis["analysis"]["rating"] == expected
    assert "rating" not in {f.name for f in dataclasses.fields(result)}


def test_analyze_nests_findings_suggestions_and_evasion_risks_as_the_contract_states():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    analysis = format_analyze(result, RUNTIME)["analysis"]
    assert list(analysis["findings"][0]) == ["category", "severity", "title", "detail"]
    assert list(analysis["suggestions"][0]) == [
        "priority", "title", "description", "codeSnippet"
    ]
    assert list(analysis["evasionRisks"][0]) == ["technique", "description", "mitigation"]
    assert isinstance(analysis["suggestions"][0]["priority"], int)


def test_analyze_carries_a_null_rule_id_for_an_ad_hoc_query():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    ad_hoc = dataclasses.replace(RUNTIME, rule_id=None)
    assert format_analyze(result, ad_hoc)["analysis"]["ruleId"] is None


def test_analyze_arrays_stay_arrays_when_empty():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    bare = dataclasses.replace(
        result, strengths=(), weaknesses=(), evasion_risks=(), mappings=(), findings=(),
        recommendations=(),
    )
    analysis = format_analyze(bare, RUNTIME)["analysis"]
    for key in ("strengths", "weaknesses", "evasionRisks", "mitreMappings",
                "findings", "suggestions"):
        assert analysis[key] == []


# B — ENHANCE


def test_enhance_produces_exactly_its_contract_field_set():
    result, _ = result_for(ReasoningOperation.ENHANCE)
    document = format_enhance(result, RUNTIME)
    assert list(document) == ["analysis"]
    assert list(document["analysis"]) == ENHANCE_KEYS


def test_enhance_carries_the_sentinels_rather_than_a_grade():
    result, _ = result_for(ReasoningOperation.ENHANCE)
    analysis = format_enhance(result, RUNTIME)["analysis"]
    assert analysis["analysisType"] == "enhance"
    assert analysis["score"] == 0
    assert analysis["rating"] == ""


def test_enhance_reports_the_original_query_as_the_input():
    result, _ = result_for(ReasoningOperation.ENHANCE)
    analysis = format_enhance(result, RUNTIME)["analysis"]
    assert analysis["inputQuery"] == result.original_rule.query
    assert analysis["enhancedQuery"] == result.enhanced_rule.query


def test_enhance_changelog_pairs_a_derived_label_with_the_model_reason():
    result, _ = result_for(ReasoningOperation.ENHANCE)
    entry = format_enhance(result, RUNTIME)["analysis"]["changelog"][0]
    assert list(entry) == ["change", "reason"]
    assert entry["change"].startswith(("Added ", "Removed ", "Changed "))
    assert entry["reason"] == result.changes[0].rationale


def test_enhance_keeps_its_mappings_under_the_new_mapping_name():
    result, _ = result_for(ReasoningOperation.ENHANCE)
    analysis = format_enhance(result, RUNTIME)["analysis"]
    assert "newMitreMappings" in analysis
    assert "mitreMappings" not in analysis


# C — GENERATE


def test_generate_produces_exactly_its_contract_field_set():
    result, _ = result_for(ReasoningOperation.GENERATE)
    document = format_generate(result, RUNTIME)
    assert list(document) == ["analysis"]
    assert list(document["analysis"]) == GENERATE_KEYS


def test_generate_uses_the_contract_schedule_defaults():
    result, _ = result_for(ReasoningOperation.GENERATE)
    analysis = format_generate(result, RUNTIME)["analysis"]
    assert analysis["interval"] == "5m"
    assert analysis["fromTime"] == "now-6m"
    assert analysis["maxSignals"] == 100
    assert analysis["references"] == []


def test_generate_keeps_score_and_risk_score_apart():
    result, _ = result_for(ReasoningOperation.GENERATE)
    analysis = format_generate(result, RUNTIME)["analysis"]
    assert analysis["score"] == result.score
    assert analysis["riskScore"] == result.generated_rule.risk_score
    assert analysis["score"] != analysis["riskScore"]


def test_generate_stores_the_query_language_under_its_api_value():
    result, _ = result_for(ReasoningOperation.GENERATE)
    analysis = format_generate(result, RUNTIME)["analysis"]
    assert result.generated_rule.language.value == "kql"
    assert analysis["language"] == "kuery"


def test_generate_omits_the_saved_rule_fields_when_nothing_was_saved():
    result, _ = result_for(ReasoningOperation.GENERATE)
    document = format_generate(result, RUNTIME)
    assert list(document) == ["analysis"]


def test_generate_emits_the_saved_rule_fields_only_when_both_are_present():
    result, _ = result_for(ReasoningOperation.GENERATE)
    document = format_generate(result, SAVED)
    assert list(document) == ["analysis", "savedRuleId", "savedRuleTitle"]
    assert document["savedRuleId"] == SAVED.saved_rule_id
    assert document["savedRuleTitle"] == SAVED.saved_rule_title

    half = dataclasses.replace(SAVED, saved_rule_title=None)
    assert list(format_generate(result, half)) == ["analysis"]


def test_generate_carries_no_rule_id_and_no_rating():
    result, _ = result_for(ReasoningOperation.GENERATE)
    analysis = format_generate(result, RUNTIME)["analysis"]
    assert "ruleId" not in analysis
    assert "rating" not in analysis


# J — no cross-operation leakage


ANALYZE_ONLY = {
    "outputQuery", "fpRisk", "feedback", "strengths", "weaknesses", "findings",
    "suggestions", "evasionRisks",
}
ENHANCE_ONLY = {
    "enhancedQuery", "changelog", "newSeverity", "newRiskScore", "newMitreMappings",
    "enhancedTitle", "enhancedDescription",
}
GENERATE_ONLY = {
    "title", "description", "query", "language", "ruleType", "severity", "riskScore",
    "tags", "interval", "fromTime", "maxSignals", "notes",
}


def test_analyze_receives_no_field_owned_by_another_operation():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    keys = set(format_analyze(result, RUNTIME)["analysis"])
    assert not keys & (ENHANCE_ONLY | GENERATE_ONLY)


def test_enhance_receives_no_field_owned_by_another_operation():
    result, _ = result_for(ReasoningOperation.ENHANCE)
    keys = set(format_enhance(result, RUNTIME)["analysis"])
    assert not keys & (ANALYZE_ONLY | GENERATE_ONLY)


def test_generate_receives_no_field_owned_by_another_operation():
    result, _ = result_for(ReasoningOperation.GENERATE)
    keys = set(format_generate(result, RUNTIME)["analysis"])
    assert not keys & (ANALYZE_ONLY | ENHANCE_ONLY)


def test_no_internal_field_name_survives_into_any_document():
    """The documents are camelCase; an internal name means a rename was missed."""
    internal = {
        "fp_risk", "evasion_risks", "code_snippet", "risk_score", "index_patterns",
        "false_positives", "investigation_guide", "rule_type", "technique_id",
        "tactic_id", "parent_technique_id", "original_rule", "enhanced_rule",
        "generated_rule", "uncertainties", "provenance", "support", "evidence",
    }
    for operation, formatter in (
        (ReasoningOperation.ANALYZE, format_analyze),
        (ReasoningOperation.ENHANCE, format_enhance),
        (ReasoningOperation.GENERATE, format_generate),
    ):
        result, _ = result_for(operation)
        document = formatter(result, RUNTIME)
        assert not set(document["analysis"]) & internal


# dispatch and structural invariants


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        (ReasoningOperation.ANALYZE, "analyze"),
        (ReasoningOperation.ENHANCE, "enhance"),
        (ReasoningOperation.GENERATE, "generate"),
    ],
)
def test_dispatch_picks_the_formatter_from_the_result_type(operation, expected):
    result, _ = result_for(operation)
    assert format_result(result, RUNTIME)["analysis"]["analysisType"] == expected


def test_formatting_a_result_as_the_wrong_operation_is_refused():
    analyze, _ = result_for(ReasoningOperation.ANALYZE)
    enhance, _ = result_for(ReasoningOperation.ENHANCE)
    with pytest.raises(OperationMismatchError):
        format_enhance(analyze, RUNTIME)
    with pytest.raises(OperationMismatchError):
        format_analyze(enhance, RUNTIME)


def test_formatting_mutates_neither_the_result_nor_the_runtime():
    for operation in BUILDERS:
        result, _ = result_for(operation)
        before = dataclasses.replace(result)
        runtime_before = dataclasses.replace(RUNTIME)
        format_result(result, RUNTIME)
        assert result == before
        assert RUNTIME == runtime_before


def test_formatting_is_deterministic():
    for operation in BUILDERS:
        result, _ = result_for(operation)
        assert format_result(result, RUNTIME) == format_result(result, RUNTIME)
