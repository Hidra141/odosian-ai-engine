"""Stage-16 over the Stage-15 semantic fields.

The boundary widened when Stage-15 gained a score, a false-positive risk,
strengths, evasion routes, tags, ATT&CK names and a code fragment. Every one of
them is a claim, and a claim that reaches the boundary unchecked is a claim the
boundary does not defend.

Results are built by running the real Stage-15 engine over a fake provider, then
altered with ``dataclasses.replace``. That is the path this layer exists to
cover: a result assembled by an application, restored from a cache or replayed
from a log never passed through Stage-15's parser, so the fault it carries is
one only this layer can catch.
"""

from __future__ import annotations

import dataclasses
import math

import pytest

from src.context.types import ContextOperation
from src.core.models import (
    AnalyzeRequest,
    EnhanceRequest,
    EvasionRisk,
    GenerateRequest,
    MappingClaim,
    MitreMapping,
)
from src.core.types import ReasoningOperation, SupportLevel, UncertaintyStatus
from src.validation import (
    EvidenceValidationError,
    StructuralValidationError,
    ValidationCategory,
    ValidationCode,
    ValidationEngine,
    attack_mappings,
    citations,
)
from tests.fixtures import stage15 as fixtures

ENGINE = ValidationEngine()

BUILDERS = {
    ReasoningOperation.ANALYZE: (
        ContextOperation.ANALYZE,
        fixtures.analyze_response,
        "analyze",
        AnalyzeRequest,
    ),
    ReasoningOperation.ENHANCE: (
        ContextOperation.ENHANCE,
        fixtures.enhance_response,
        "enhance",
        EnhanceRequest,
    ),
    ReasoningOperation.GENERATE: (
        ContextOperation.GENERATE,
        fixtures.generate_response,
        "generate",
        GenerateRequest,
    ),
}

SCORED = [ReasoningOperation.ANALYZE, ReasoningOperation.GENERATE]


def result_for(operation: ReasoningOperation):
    """Return a real Stage-15 result and the package that produced it."""
    context_operation, response_of, call, request_of = BUILDERS[operation]
    package = fixtures.context_package(context_operation)
    engine = fixtures.engine_of(fixtures.provider_returning([response_of(package)]))
    return getattr(engine, call)(request_of(package=package)), package


def codes(report):
    return [issue.code for issue in report.issues]


def remap(result, **changes):
    """Return the result with its first mapping claim altered."""
    claim = dataclasses.replace(result.mappings[0], **changes)
    return dataclasses.replace(result, mappings=(claim, *result.mappings[1:]))


def retag(result, tags):
    """Return the result with its produced rule's tags replaced."""
    field = "enhanced_rule" if hasattr(result, "enhanced_rule") else "generated_rule"
    rule = dataclasses.replace(getattr(result, field), tags=tuple(tags))
    return dataclasses.replace(result, **{field: rule})


def resnip(result, snippet):
    """Return the result with its first recommendation's code fragment replaced."""
    first = dataclasses.replace(result.recommendations[0], code_snippet=snippet)
    return dataclasses.replace(result, recommendations=(first, *result.recommendations[1:]))


# A — code_snippet reaches the security and grounding checks


def test_a_faithful_code_snippet_is_accepted():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert result.recommendations[0].code_snippet
    assert ENGINE.validate(result, package).is_valid


def test_a_credential_hidden_in_a_code_snippet_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    leaking = resnip(result, "api_key=AIzaSyA1234567890123456789012345678901234")
    report = ENGINE.validate(leaking, package)
    assert ValidationCode.CREDENTIAL_IN_RESULT in codes(report)
    assert any(i.path == "recommendations[0].code_snippet" for i in report.errors)


def test_a_fence_marker_in_a_code_snippet_is_rejected():
    from src.core.context_view import FENCE_END

    result, package = result_for(ReasoningOperation.ANALYZE)
    echoed = resnip(result, f"process.name:* {FENCE_END}")
    assert ValidationCode.FENCE_ARTIFACT in codes(ENGINE.validate(echoed, package))


def test_a_template_placeholder_in_a_code_snippet_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    echoed = resnip(result, "process.name:{{OUTPUT_FORMAT}}")
    assert ValidationCode.TEMPLATE_ARTIFACT in codes(ENGINE.validate(echoed, package))


def test_an_invented_url_in_a_code_snippet_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = resnip(result, "url.original:'https://example.invalid/payload'")
    assert ValidationCode.FABRICATED_REFERENCE in codes(ENGINE.validate(invented, package))


def test_a_fabricated_identifier_in_a_code_snippet_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = resnip(result, "threat.technique.id:'T9999'")
    report = ENGINE.validate(invented, package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert "T9999" in str(report.errors[0])


def test_a_multiline_code_snippet_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = resnip(result, "process.name:*\nand process.args:*")
    assert ValidationCode.MULTILINE_STRING in codes(ENGINE.validate(broken, package))


def test_an_empty_code_snippet_is_allowed():
    """Not every recommendation can be expressed as a fragment."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert ENGINE.validate(resnip(result, ""), package).is_valid


# B, C — analyze mapping identifiers


def test_an_analyze_mapping_with_supplied_identifiers_is_accepted():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert result.mappings[0].technique_id == "T1059.001"
    assert ENGINE.validate(result, package).is_valid


def test_a_fabricated_analyze_mapping_technique_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    with pytest.raises(EvidenceValidationError) as error:
        ENGINE.validate_or_raise(remap(result, technique_id="T9999"), package)
    report = error.value.report
    assert ValidationCode.FABRICATED_IDENTIFIER in report.codes()
    assert [i.path for i in report.errors] == ["mappings[0].technique_id"]


def test_a_fabricated_analyze_mapping_tactic_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, tactic_id="TA9999"), package)
    assert [i.path for i in report.errors] == ["mappings[0].tactic_id"]
    assert ValidationCode.FABRICATED_IDENTIFIER in report.codes()


def test_both_fabricated_analyze_mapping_identifiers_are_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, tactic_id="TA9999", technique_id="T9999"), package)
    assert [i.path for i in report.errors] == [
        "mappings[0].tactic_id",
        "mappings[0].technique_id",
    ]


def test_an_empty_analyze_mapping_tactic_is_not_a_false_positive():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert result.mappings[0].tactic_id == ""
    assert ENGINE.validate(remap(result, tactic_id="   "), package).is_valid


# D — analyze mapping citations


def test_an_analyze_mapping_citation_is_walked_like_any_other():
    result, _ = result_for(ReasoningOperation.ANALYZE)
    paths = [path for path, _ in citations(result)]
    assert "mappings[0].evidence[0]" in paths


def test_an_unknown_analyze_mapping_citation_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    claim = result.mappings[0]
    citation = dataclasses.replace(claim.evidence[0], item_id="ctx-never-supplied")
    report = ENGINE.validate(remap(result, evidence=(citation,)), package)
    assert ValidationCode.UNKNOWN_ITEM in codes(report)
    assert any(i.path == "mappings[0].evidence[0].item_id" for i in report.errors)


def test_an_analyze_mapping_citation_naming_the_wrong_source_is_rejected():
    from src.core.types import EvidenceSource

    result, package = result_for(ReasoningOperation.ANALYZE)
    claim = result.mappings[0]
    citation = dataclasses.replace(claim.evidence[0], source=EvidenceSource.SIGMA)
    report = ENGINE.validate(remap(result, evidence=(citation,)), package)
    assert ValidationCode.CITATION_SOURCE_MISMATCH in codes(report)
    assert report.of_category(ValidationCategory.PROVENANCE)


def test_several_analyze_mapping_citations_are_each_checked():
    result, package = result_for(ReasoningOperation.ANALYZE)
    good = result.mappings[0].evidence[0]
    bad = dataclasses.replace(good, item_id="ctx-never-supplied")
    report = ENGINE.validate(remap(result, evidence=(good, bad, good)), package)
    assert [i.path for i in report.errors] == ["mappings[0].evidence[1].item_id"]


# E — MITRE names


def test_a_mapping_name_the_material_carries_is_accepted():
    """The corpus text names the technique, so copying that name is grounded."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    supplied_name = "PowerShell"
    assert supplied_name in "\n".join(item.text for item in package.items)
    assert ENGINE.validate(remap(result, technique_name=supplied_name), package).is_valid


def test_a_remembered_mapping_name_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, technique_name="Ingress Tool Transfer"), package)
    assert ValidationCode.FABRICATED_NAME in codes(report)
    assert any(i.path == "mappings[0].technique_name" for i in report.errors)


def test_a_fabricated_tactic_name_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, tactic_name="Lateral Movement"), package)
    assert [i.path for i in report.errors] == ["mappings[0].tactic_name"]


def test_an_empty_mapping_name_is_accepted():
    """The contract asks for an empty name where the material names nothing."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert result.mappings[0].technique_name == ""
    assert ENGINE.validate(result, package).is_valid


def test_a_correct_identifier_does_not_licence_a_remembered_name():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(
        remap(result, technique_id="T1059.001", technique_name="Nonexistent Technique"),
        package,
    )
    assert ValidationCode.FABRICATED_IDENTIFIER not in codes(report)
    assert ValidationCode.FABRICATED_NAME in codes(report)


def test_a_name_is_matched_past_harmless_case_and_spacing():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert ENGINE.validate(remap(result, technique_name="  powershell  "), package).is_valid


def test_names_on_a_produced_rule_are_checked_too():
    result, package = result_for(ReasoningOperation.GENERATE)
    fabricated = dataclasses.replace(
        result.generated_rule,
        mitre=(
            MitreMapping(
                tactic_id="",
                technique_id="T1059.001",
                technique_name="Remembered Name",
                confidence=0.5,
            ),
        ),
    )
    report = ENGINE.validate(dataclasses.replace(result, generated_rule=fabricated), package)
    assert ValidationCode.FABRICATED_NAME in codes(report)
    assert any(i.path == "generated_rule.mitre[0].technique_name" for i in report.errors)


# F — score boundaries


@pytest.mark.parametrize("operation", SCORED, ids=lambda o: o.value)
@pytest.mark.parametrize("value", [0, 1, 50, 99, 100])
def test_a_score_inside_its_range_is_accepted(operation, value):
    result, package = result_for(operation)
    assert ENGINE.validate(dataclasses.replace(result, score=value), package).is_valid


@pytest.mark.parametrize("operation", SCORED, ids=lambda o: o.value)
@pytest.mark.parametrize("value", [-1, 101, 1000])
def test_a_score_outside_its_range_is_rejected(operation, value):
    result, package = result_for(operation)
    with pytest.raises(StructuralValidationError) as error:
        ENGINE.validate_or_raise(dataclasses.replace(result, score=value), package)
    assert [i.path for i in error.value.report.errors] == ["score"]
    assert ValidationCode.OUT_OF_RANGE in error.value.report.codes()


@pytest.mark.parametrize(
    "value", [math.nan, math.inf, -math.inf], ids=["nan", "inf", "-inf"]
)
def test_a_non_finite_score_is_rejected(value):
    """NaN fails every comparison, so a range test alone would let it through."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(dataclasses.replace(result, score=value), package)
    assert not report.is_valid
    assert ValidationCode.OUT_OF_RANGE in codes(report)


@pytest.mark.parametrize("value", ["50", None, True], ids=["string", "none", "bool"])
def test_a_score_of_the_wrong_type_is_rejected(value):
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(dataclasses.replace(result, score=value), package)
    assert ValidationCode.OUT_OF_RANGE in codes(report)
    assert "is not a number" in str(report.errors[0])


def test_validation_never_changes_the_score():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = dataclasses.replace(result, score=140)
    ENGINE.validate(broken, package)
    assert broken.score == 140


# G — mapping confidence boundaries


@pytest.mark.parametrize("value", [0.0, 0.1, 0.5, 0.99, 1.0])
def test_a_mapping_confidence_inside_its_range_is_accepted(value):
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert ENGINE.validate(remap(result, confidence=value), package).is_valid


@pytest.mark.parametrize("value", [-0.1, 1.1, 100])
def test_a_mapping_confidence_outside_its_range_is_rejected(value):
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, confidence=value), package)
    assert [i.path for i in report.errors] == ["mappings[0].confidence"]
    assert ValidationCode.OUT_OF_RANGE in report.codes()


@pytest.mark.parametrize(
    "value", [math.nan, math.inf, -math.inf], ids=["nan", "inf", "-inf"]
)
def test_a_non_finite_mapping_confidence_is_rejected(value):
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, confidence=value), package)
    assert ValidationCode.OUT_OF_RANGE in codes(report)


def test_a_generated_rule_mapping_confidence_is_bounded_too():
    result, package = result_for(ReasoningOperation.GENERATE)
    rule = dataclasses.replace(
        result.generated_rule,
        mitre=(MitreMapping(tactic_id="", technique_id="T1059.001", confidence=7.0),),
    )
    report = ENGINE.validate(dataclasses.replace(result, generated_rule=rule), package)
    assert [i.path for i in report.errors] == ["generated_rule.mitre[0].confidence"]


def test_an_enhanced_rule_mapping_confidence_is_bounded_too():
    result, package = result_for(ReasoningOperation.ENHANCE)
    rule = dataclasses.replace(
        result.enhanced_rule,
        mitre=(MitreMapping(tactic_id="", technique_id="T1059.001", confidence=-2.0),),
    )
    report = ENGINE.validate(dataclasses.replace(result, enhanced_rule=rule), package)
    assert [i.path for i in report.errors] == ["enhanced_rule.mitre[0].confidence"]


def test_every_mapping_location_is_reached_by_one_traversal():
    result, _ = result_for(ReasoningOperation.GENERATE)
    paths = [path for path, _ in attack_mappings(result)]
    assert "mappings[0]" in paths
    assert "generated_rule.mitre[0]" in paths


def test_confidence_is_never_rescaled_to_a_percentage():
    """0..100 is Stage-17's presentation, not this layer's meaning."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    ENGINE.validate(result, package)
    assert result.mappings[0].confidence == 0.75


# H — strengths grounding


def test_grounded_strengths_are_accepted():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert result.strengths
    assert ENGINE.validate(result, package).is_valid


def test_a_paraphrased_strength_is_not_rejected_for_wording():
    """Prose is summarised, not copied. Only what it asserts is checkable."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    reworded = dataclasses.replace(
        result, strengths=("The rule focuses on the interpreter itself, which is sound.",)
    )
    assert ENGINE.validate(reworded, package).is_valid


def test_a_strength_asserting_an_unsupplied_identifier_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = dataclasses.replace(result, strengths=("Provides coverage of T9999.",))
    report = ENGINE.validate(invented, package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "strengths[0]" for i in report.errors)


def test_an_empty_strength_is_rejected_as_a_missing_value():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(dataclasses.replace(result, strengths=("  ",)), package)
    assert ValidationCode.MISSING_VALUE in codes(report)


def test_no_strengths_at_all_is_a_valid_answer():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert ENGINE.validate(dataclasses.replace(result, strengths=()), package).is_valid


def test_a_credential_in_a_strength_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    leaking = dataclasses.replace(
        result, strengths=("Uses api_key=AIzaSyA1234567890123456789012345678901234",)
    )
    assert ValidationCode.CREDENTIAL_IN_RESULT in codes(ENGINE.validate(leaking, package))


# I — evasion_risks grounding


def test_grounded_evasion_risks_are_accepted():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert result.evasion_risks
    assert ENGINE.validate(result, package).is_valid


def test_an_evasion_risk_asserting_an_unsupplied_identifier_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = dataclasses.replace(
        result,
        evasion_risks=(
            EvasionRisk(
                technique="pivot",
                description="An attacker could pivot to T9999 instead.",
                mitigation="Match the supplied abbreviations.",
            ),
        ),
    )
    report = ENGINE.validate(invented, package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "evasion_risks[0].description" for i in report.errors)


def test_an_invented_advisory_url_in_an_evasion_risk_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = dataclasses.replace(
        result,
        evasion_risks=(
            EvasionRisk(
                technique="documented bypass",
                description="See https://example.invalid/bypass for the technique.",
                mitigation="Match the supplied abbreviations.",
            ),
        ),
    )
    assert ValidationCode.FABRICATED_REFERENCE in codes(ENGINE.validate(invented, package))


def test_no_evasion_risks_at_all_is_a_valid_answer():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert ENGINE.validate(dataclasses.replace(result, evasion_risks=()), package).is_valid


# J — tags


def test_valid_tags_are_accepted():
    result, package = result_for(ReasoningOperation.GENERATE)
    assert result.generated_rule.tags == ("Windows", "PowerShell")
    assert ENGINE.validate(result, package).is_valid


def test_an_ordinary_label_needs_no_literal_evidence():
    """Tags classify. They are not assertions about the corpus."""
    result, package = result_for(ReasoningOperation.GENERATE)
    assert ENGINE.validate(retag(result, ["Execution", "Endpoint"]), package).is_valid


def test_an_empty_tag_is_rejected():
    result, package = result_for(ReasoningOperation.GENERATE)
    report = ENGINE.validate(retag(result, ["Windows", ""]), package)
    assert ValidationCode.MISSING_VALUE in codes(report)
    assert any(i.path == "generated_rule.tags[1]" for i in report.errors)


def test_a_multiline_tag_is_rejected():
    result, package = result_for(ReasoningOperation.GENERATE)
    report = ENGINE.validate(retag(result, ["Windows\nPowerShell"]), package)
    assert ValidationCode.MULTILINE_STRING in codes(report)


def test_a_tag_asserting_an_unsupplied_identifier_is_rejected():
    result, package = result_for(ReasoningOperation.GENERATE)
    report = ENGINE.validate(retag(result, ["Windows", "T9999"]), package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "generated_rule.tags[1]" for i in report.errors)


def test_a_credential_shaped_tag_is_rejected():
    result, package = result_for(ReasoningOperation.GENERATE)
    leaking = retag(result, ["api_key=AIzaSyA1234567890123456789012345678901234"])
    assert ValidationCode.CREDENTIAL_IN_RESULT in codes(ENGINE.validate(leaking, package))


def test_no_tags_at_all_is_a_valid_answer():
    result, package = result_for(ReasoningOperation.GENERATE)
    assert ENGINE.validate(retag(result, []), package).is_valid


# K — uncertainty is untouched by any of this


@pytest.mark.parametrize("operation", list(BUILDERS), ids=lambda o: o.value)
def test_uncertainty_still_survives_the_widened_boundary(operation):
    result, package = result_for(operation)
    carried = {entry.identifier: entry for entry in result.uncertainties}
    assert carried["T1562"].status is UncertaintyStatus.UNRESOLVED
    assert carried["TA0011"].status is UncertaintyStatus.UNRESOLVED
    assert carried["M1013"].status is UncertaintyStatus.AMBIGUOUS
    assert carried["M1013"].candidates == ("enterprise:M1013", "mobile:M1013")
    assert ENGINE.validate(result, package).is_valid


def test_an_analyze_mapping_may_not_claim_an_unsettled_identifier_as_fact():
    result, package = result_for(ReasoningOperation.ANALYZE)
    claimed = remap(result, technique_id="T1562", support=SupportLevel.SUPPORTED)
    report = ENGINE.validate(claimed, package)
    assert ValidationCode.UNCERTAINTY_PRESENTED_AS_FACT in codes(report)
    assert any(i.path == "mappings[0].technique_id" for i in report.errors)


def test_an_analyze_mapping_may_carry_an_unsettled_identifier_without_claiming_support():
    result, package = result_for(ReasoningOperation.ANALYZE)
    carried = remap(
        result, technique_id="T1562", support=SupportLevel.PARTIALLY_SUPPORTED
    )
    assert ENGINE.validate(carried, package).is_valid


def test_validation_resolves_no_uncertainty_and_drops_no_candidate():
    result, package = result_for(ReasoningOperation.ANALYZE)
    before = tuple((e.identifier, e.status, e.candidates) for e in result.uncertainties)
    ENGINE.validate(result, package)
    after = tuple((e.identifier, e.status, e.candidates) for e in result.uncertainties)
    assert after == before


# multiple faults, and stable ordering


def test_every_new_fault_in_one_result_is_reported_together():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = remap(
        dataclasses.replace(
            result,
            score=140,
            strengths=("Covers T9999.",),
            evasion_risks=(
                EvasionRisk(
                    technique="pivot",
                    description="Pivots to T8888.",
                    mitigation="Match the supplied abbreviations.",
                ),
            ),
        ),
        confidence=3.0,
        technique_name="Remembered Name",
    )
    report = ENGINE.validate(broken, package)
    assert not report.is_valid
    found = set(codes(report))
    assert {
        ValidationCode.OUT_OF_RANGE,
        ValidationCode.FABRICATED_IDENTIFIER,
        ValidationCode.FABRICATED_NAME,
    } <= found


def test_the_widened_report_is_still_deterministic_and_ordered():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = remap(
        dataclasses.replace(result, score=140, strengths=("Covers T9999.",)),
        confidence=3.0,
        technique_name="Remembered Name",
    )
    first = ENGINE.validate(broken, package)
    second = ENGINE.validate(broken, package)
    assert first == second
    assert [i.sort_key for i in first.issues] == sorted(i.sort_key for i in first.issues)


def test_a_mapping_claim_built_by_hand_is_judged_like_any_other():
    """The path this layer exists for: a result that never met Stage-15's parser."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    forged = dataclasses.replace(
        result,
        mappings=(
            MappingClaim(
                tactic_id="TA9999",
                technique_id="T9999",
                support=SupportLevel.SUPPORTED,
                evidence=(),
                tactic_name="Invented Tactic",
                technique_name="Invented Technique",
                confidence=5.0,
            ),
        ),
    )
    report = ENGINE.validate(forged, package)
    assert not report.is_valid
    assert {
        ValidationCode.FABRICATED_IDENTIFIER,
        ValidationCode.FABRICATED_NAME,
        ValidationCode.OUT_OF_RANGE,
    } <= set(codes(report))


# Phase C — the compatibility fields reach the boundary


def test_a_fabricated_parent_technique_name_is_rejected():
    """A parent name nobody supplied is a fabrication like any other name."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(
        remap(result, parent_technique_name="Remembered Parent"), package
    )
    assert ValidationCode.FABRICATED_NAME in codes(report)
    assert any(i.path == "mappings[0].parent_technique_name" for i in report.errors)


def test_a_parent_name_the_material_carries_is_accepted():
    """Grounding decides, exactly as for any other name."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    supplied = "\n".join(item.text for item in package.items)
    assert "PowerShell" in supplied
    assert ENGINE.validate(
        remap(result, parent_technique_name="PowerShell"), package
    ).is_valid


def test_the_corpus_supplies_the_parent_technique_for_a_sub_technique():
    """Blocker 6 rests on this: the parent name is in the material, not invented.

    Asserted against the real MITRE record rather than the fixture, because the
    fixture writes its own chunk text and this is a claim about the corpus.
    """
    import json
    from pathlib import Path

    for line in Path("resources/knowledge/mitre/mitre.jsonl").open(encoding="utf-8"):
        record = json.loads(line)
        if record.get("sourceId") == "enterprise:T1059.001":
            assert record["metadata"]["parentTechniqueId"] == "T1059"
            assert (
                "Parent Technique: Command and Scripting Interpreter (T1059)"
                in record["text"]
            )
            break
    else:
        raise AssertionError("the T1059.001 record is missing from the corpus")


def test_a_fabricated_parent_technique_id_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, parent_technique_id="T9999"), package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "mappings[0].parent_technique_id" for i in report.errors)


def test_a_weakness_asserting_an_unsupplied_identifier_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = dataclasses.replace(result, weaknesses=("Misses T9999 entirely.",))
    report = ENGINE.validate(invented, package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "weaknesses[0]" for i in report.errors)


def test_an_empty_weakness_is_rejected_as_a_missing_value():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(dataclasses.replace(result, weaknesses=("  ",)), package)
    assert ValidationCode.MISSING_VALUE in codes(report)


def test_no_weaknesses_at_all_is_a_valid_answer():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert ENGINE.validate(dataclasses.replace(result, weaknesses=()), package).is_valid


def test_every_part_of_an_evasion_risk_is_scanned():
    result, package = result_for(ReasoningOperation.ANALYZE)
    leaking = dataclasses.replace(
        result,
        evasion_risks=(
            EvasionRisk(
                technique="flag",
                description="ordinary prose",
                mitigation="api_key=AIzaSyA1234567890123456789012345678901234",
            ),
        ),
    )
    report = ENGINE.validate(leaking, package)
    assert ValidationCode.CREDENTIAL_IN_RESULT in codes(report)
    assert any(i.path == "evasion_risks[0].mitigation" for i in report.errors)


def test_an_empty_evasion_risk_part_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = dataclasses.replace(
        result,
        evasion_risks=(EvasionRisk(technique="", description="d", mitigation="m"),),
    )
    report = ENGINE.validate(broken, package)
    assert ValidationCode.MISSING_VALUE in codes(report)
    assert any(i.path == "evasion_risks[0].technique" for i in report.errors)


def test_generate_notes_are_scanned_like_any_other_text():
    result, package = result_for(ReasoningOperation.GENERATE)
    invented = dataclasses.replace(result, notes="Follow up on T9999 coverage.")
    report = ENGINE.validate(invented, package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "notes" for i in report.errors)


def test_empty_generate_notes_are_accepted():
    result, package = result_for(ReasoningOperation.GENERATE)
    assert ENGINE.validate(dataclasses.replace(result, notes=""), package).is_valid
