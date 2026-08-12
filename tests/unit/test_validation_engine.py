"""Stage-16 validation engine.

The post-reasoning boundary: what it accepts, what it refuses, and why.

Results are built by running the real Stage-15 engine over a fake provider, so
every case starts from an object the pipeline could actually produce. Where a
case needs a fault the parser would reject — a wrong type, an out-of-range
number — the typed result is constructed directly with ``dataclasses.replace``,
which is exactly the path this layer exists to cover.
"""

from __future__ import annotations

import dataclasses

import pytest

from src.context.models import ContextPackage, RuleContext
from src.context.types import ContextOperation
from src.core.models import (
    AnalyzeRequest,
    EnhanceRequest,
    GenerateRequest,
    MitreMapping,
    Uncertainty,
)
from src.core.types import (
    EvidenceSource,
    OutputLanguage,
    OutputRuleType,
    ReasoningOperation,
    SupportLevel,
    UncertaintyStatus,
)
from src.validation import (
    EvidenceValidationError,
    IssueSeverity,
    SecurityValidationError,
    StructuralValidationError,
    UncertaintyValidationError,
    ValidationCategory,
    ValidationCode,
    ValidationEngine,
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


def result_for(operation: ReasoningOperation, payload=None):
    """Return a real Stage-15 result and the package that produced it."""
    context_operation, response_of, call, request_of = BUILDERS[operation]
    package = fixtures.context_package(context_operation)
    body = payload(package) if payload is not None else response_of(package)
    engine = fixtures.engine_of(fixtures.provider_returning([body]))
    return getattr(engine, call)(request_of(package=package)), package


def codes(report):
    return [issue.code for issue in report.issues]


# 1-3 — the happy paths


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_a_faithful_result_is_accepted(operation):
    result, package = result_for(operation)
    report = ENGINE.validate(result, package)
    assert report.is_valid
    assert report.issue_count == 0
    assert report.operation is operation
    assert ENGINE.accepts(result, package)
    assert ENGINE.validate_or_raise(result, package) is result


# 4-7 — structural


def test_a_missing_required_value_is_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(dataclasses.replace(result, summary="   "), package)
    assert ValidationCode.MISSING_VALUE in codes(report)
    assert not report.is_valid
    assert report.issues[0].path == "summary"


def test_a_value_outside_its_range_is_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(dataclasses.replace(result, confidence=1.4), package)
    assert ValidationCode.OUT_OF_RANGE in codes(report)


def test_a_multiline_string_is_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = dataclasses.replace(result, summary="first line\nsecond line")
    assert ValidationCode.MULTILINE_STRING in codes(ENGINE.validate(broken, package))


def test_an_operation_mismatch_is_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(result, package, operation=ReasoningOperation.ENHANCE)
    assert ValidationCode.OPERATION_MISMATCH in codes(report)
    assert ValidationCode.RESULT_TYPE_MISMATCH in codes(report)


def test_the_result_type_and_the_schema_agree_on_every_field():
    """The schema drift guard: no undeclared field, no declared field missing."""
    for operation in ReasoningOperation:
        result, package = result_for(operation)
        report = ENGINE.validate(result, package)
        assert ValidationCode.UNDECLARED_FIELD not in codes(report)
        assert ValidationCode.MISSING_VALUE not in codes(report)


def test_a_duplicate_identifier_is_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    twice = dataclasses.replace(result, findings=(result.findings[0], result.findings[0]))
    assert ValidationCode.DUPLICATE_ID in codes(ENGINE.validate(twice, package))


def test_a_recommendation_addressing_an_unknown_finding_is_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = dataclasses.replace(
        result,
        recommendations=(dataclasses.replace(result.recommendations[0], addresses=("F9",)),),
    )
    assert ValidationCode.UNKNOWN_REFERENCE in codes(ENGINE.validate(broken, package))


def test_an_impossible_combination_is_reported():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = dataclasses.replace(
        result,
        uncertainties=(
            Uncertainty("T1562", UncertaintyStatus.UNRESOLVED, ("something",), "kept"),
            *result.uncertainties[1:],
        ),
    )
    assert ValidationCode.IMPOSSIBLE_COMBINATION in codes(ENGINE.validate(broken, package))


# 8-9, 19-20 — evidence


def test_a_citation_of_an_unsupplied_item_is_rejected():
    """Stage-15 refuses this at the parse boundary; Stage-16 refuses it again."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(_recite(result, item_id="retrieval:9999"), package)
    assert ValidationCode.UNKNOWN_ITEM in codes(report)
    assert not report.is_valid


def test_a_fabricated_identifier_in_a_citation_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(_recite(result, identifier="T1218.011"), package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)


def test_a_supported_claim_that_cites_nothing_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    bare = dataclasses.replace(
        result, findings=(dataclasses.replace(result.findings[0], evidence=()),)
    )
    assert ValidationCode.UNSUPPORTED_CLAIM in codes(ENGINE.validate(bare, package))


def test_several_valid_citations_are_all_accepted():
    def payload(pkg):
        body = fixtures.analyze_response(pkg)
        for source in ("lolbas", "elastic", "sigma"):
            item = next(i for i in pkg.items if i.source and i.source.value == source)
            body["findings"][0]["evidence"].append(
                {"item_id": item.item_id, "source": source, "identifier": "", "detail": "seen"}
            )
        return body

    result, package = result_for(ReasoningOperation.ANALYZE, payload)
    report = ENGINE.validate(result, package)
    assert report.is_valid
    assert len(result.cited_item_ids()) == 4


def test_an_unsupported_finding_with_no_evidence_is_accepted():
    """Empty evidence is legitimate when the finding reports an absence."""

    def payload(pkg):
        body = fixtures.analyze_response(pkg)
        body["findings"][0]["evidence"] = []
        body["findings"][0]["support"] = "unsupported"
        body["findings"][0]["confidence"] = 0.2
        return body

    result, package = result_for(ReasoningOperation.ANALYZE, payload)
    assert ENGINE.validate(result, package).is_valid


# 10-13 — uncertainty


@pytest.mark.parametrize("identifier", ["T1562", "TA0011"])
def test_an_unresolved_identifier_may_not_be_promoted(identifier):
    """Dropping an unresolved identifier is how a result would claim it resolved."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    kept = tuple(e for e in result.uncertainties if e.identifier != identifier)
    report = ENGINE.validate(dataclasses.replace(result, uncertainties=kept), package)
    assert ValidationCode.UNCERTAINTY_DROPPED in codes(report)
    assert not report.is_valid
    assert identifier in str(report.errors[0])


@pytest.mark.parametrize("identifier", ["T1562", "TA0011"])
def test_an_unresolved_identifier_may_not_change_status(identifier):
    result, package = result_for(ReasoningOperation.ANALYZE)
    changed = tuple(
        dataclasses.replace(entry, status=UncertaintyStatus.AMBIGUOUS, candidates=("x",))
        if entry.identifier == identifier
        else entry
        for entry in result.uncertainties
    )
    report = ENGINE.validate(dataclasses.replace(result, uncertainties=changed), package)
    assert ValidationCode.UNCERTAINTY_STATUS_PROMOTED in codes(report)


def test_an_ambiguous_identifier_may_not_be_narrowed():
    result, package = result_for(ReasoningOperation.ANALYZE)
    narrowed = tuple(
        dataclasses.replace(entry, candidates=(entry.candidates[0],))
        if entry.identifier == "M1013"
        else entry
        for entry in result.uncertainties
    )
    report = ENGINE.validate(dataclasses.replace(result, uncertainties=narrowed), package)
    assert ValidationCode.AMBIGUITY_NARROWED in codes(report)
    assert "mobile:M1013" in str(report.errors[0])


def test_an_ambiguous_identifier_may_not_be_selected_without_support():
    """Citing an ambiguous identifier as established is refused."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    asserted = _recite(result, identifier="M1013", support=SupportLevel.SUPPORTED)
    assert ValidationCode.UNCERTAINTY_PRESENTED_AS_FACT in codes(
        ENGINE.validate(asserted, package)
    )


def test_an_invented_uncertainty_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = (
        *result.uncertainties,
        Uncertainty("T9999", UncertaintyStatus.UNRESOLVED, (), "invented"),
    )
    report = ENGINE.validate(dataclasses.replace(result, uncertainties=invented), package)
    assert ValidationCode.FABRICATED_UNCERTAINTY in codes(report)


def test_an_invented_candidate_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    grown = tuple(
        dataclasses.replace(entry, candidates=(*entry.candidates, "ics:M1013"))
        if entry.identifier == "M1013"
        else entry
        for entry in result.uncertainties
    )
    assert ValidationCode.FABRICATED_CANDIDATE in codes(
        ENGINE.validate(dataclasses.replace(result, uncertainties=grown), package)
    )


# 14-16 — rule integrity


def test_a_fabricated_attack_identifier_in_a_produced_rule_is_rejected():
    """The live TA0002 case: a tactic the supplied material never contained."""
    result, package = result_for(ReasoningOperation.ENHANCE)
    fabricated = dataclasses.replace(
        result.enhanced_rule, mitre=(MitreMapping(tactic_id="TA0002", technique_id="T1059.001"),)
    )
    report = ENGINE.validate(dataclasses.replace(result, enhanced_rule=fabricated), package)
    assert ValidationCode.FABRICATED_MAPPING in codes(report)
    assert not report.is_valid
    assert "TA0002" in str(report.errors[0])


def test_a_rule_whose_type_and_language_disagree_is_rejected():
    result, package = result_for(ReasoningOperation.GENERATE)
    broken = dataclasses.replace(
        result.generated_rule, rule_type=OutputRuleType.EQL, language=OutputLanguage.KQL
    )
    report = ENGINE.validate(dataclasses.replace(result, generated_rule=broken), package)
    assert ValidationCode.LANGUAGE_TYPE_MISMATCH in codes(report)


def test_an_incomplete_generated_rule_is_rejected():
    result, package = result_for(ReasoningOperation.GENERATE)
    broken = dataclasses.replace(result.generated_rule, query="  ", investigation_guide="")
    report = ENGINE.validate(dataclasses.replace(result, generated_rule=broken), package)
    assert codes(report).count(ValidationCode.INCOMPLETE_RULE) == 2


def test_an_enhanced_rule_that_lost_the_original_query_is_rejected():
    result, package = result_for(ReasoningOperation.ENHANCE)
    altered = dataclasses.replace(result.original_rule, query="process.name:cmd.exe")
    report = ENGINE.validate(dataclasses.replace(result, original_rule=altered), package)
    assert ValidationCode.ORIGINAL_RULE_ALTERED in codes(report)


def test_an_enhancement_that_changed_nothing_is_rejected():
    result, package = result_for(ReasoningOperation.ENHANCE)
    same = dataclasses.replace(result.enhanced_rule, query=result.original_rule.query)
    report = ENGINE.validate(dataclasses.replace(result, enhanced_rule=same), package)
    assert ValidationCode.RULE_UNCHANGED in codes(report)


def test_an_off_band_risk_score_warns_without_blocking():
    result, package = result_for(ReasoningOperation.GENERATE)
    odd = dataclasses.replace(result.generated_rule, risk_score=95)
    report = ENGINE.validate(dataclasses.replace(result, generated_rule=odd), package)
    assert ValidationCode.RISK_SEVERITY_MISMATCH in codes(report)
    assert report.warnings and report.is_valid


# mapping claims — the identifiers a generated rule asserts outside a citation


def test_a_mapping_claiming_supplied_identifiers_is_accepted():
    """A — both ids occur in the supplied material, so nothing is fabricated."""
    result, package = result_for(ReasoningOperation.GENERATE)
    mapped = _remap(
        result,
        tactic_id="TA0011",
        technique_id="T1059.001",
        support=SupportLevel.UNSUPPORTED,
    )
    report = ENGINE.validate(mapped, package)
    assert report.is_valid
    assert ValidationCode.FABRICATED_IDENTIFIER not in codes(report)


def test_a_fabricated_mapping_technique_id_is_rejected():
    """B — the technique the material never carried."""
    result, package = result_for(ReasoningOperation.GENERATE)
    with pytest.raises(EvidenceValidationError) as error:
        ENGINE.validate_or_raise(_remap(result, technique_id="T9999"), package)
    report = error.value.report
    assert ValidationCode.FABRICATED_IDENTIFIER in report.codes()
    assert [issue.path for issue in report.errors] == ["mappings[0].technique_id"]
    assert "T9999" in error.value.issues[0]


def test_a_fabricated_mapping_tactic_id_is_rejected():
    """C — the tactic the material never carried, which the live model invented."""
    result, package = result_for(ReasoningOperation.GENERATE)
    with pytest.raises(EvidenceValidationError) as error:
        ENGINE.validate_or_raise(_remap(result, tactic_id="TA9999"), package)
    report = error.value.report
    assert ValidationCode.FABRICATED_IDENTIFIER in report.codes()
    assert [issue.path for issue in report.errors] == ["mappings[0].tactic_id"]
    assert "TA9999" in error.value.issues[0]


def test_a_mapping_fabricating_both_identifiers_reports_both():
    """D — neither id is supplied, and neither is allowed to pass unremarked."""
    result, package = result_for(ReasoningOperation.GENERATE)
    report = ENGINE.validate(
        _remap(result, tactic_id="TA9999", technique_id="T9999"), package
    )
    assert not report.is_valid
    assert [issue.path for issue in report.errors] == [
        "mappings[0].tactic_id",
        "mappings[0].technique_id",
    ]
    assert set(report.codes()) == {ValidationCode.FABRICATED_IDENTIFIER}


def test_a_mapping_stating_no_tactic_claims_nothing():
    """An empty id asserts nothing about the material, so nothing is checked."""
    result, package = result_for(ReasoningOperation.GENERATE)
    assert result.mappings[0].tactic_id == ""
    report = ENGINE.validate(result, package)
    assert report.is_valid


@pytest.mark.parametrize("identifier", ["T1562", "TA0011", "M1013"])
def test_a_mapping_may_not_present_an_unsettled_identifier_as_fact(identifier):
    """E — the uncertainty rules hold for a mapping claim as for any other."""
    result, package = result_for(ReasoningOperation.GENERATE)
    mapped = _remap(result, tactic_id=identifier, support=SupportLevel.SUPPORTED)
    report = ENGINE.validate(mapped, package)
    assert ValidationCode.UNCERTAINTY_PRESENTED_AS_FACT in codes(report)
    assert not report.is_valid
    assert [
        issue.path for issue in report.of_category(ValidationCategory.UNCERTAINTY)
    ] == ["mappings[0].tactic_id"]
    assert ValidationCode.FABRICATED_IDENTIFIER not in codes(report)


@pytest.mark.parametrize("identifier", ["T1562", "TA0011", "M1013"])
def test_a_mapping_may_rest_on_an_unsettled_identifier_without_claiming_support(identifier):
    """E — carrying an unsettled id is allowed; asserting it as established is not."""
    result, package = result_for(ReasoningOperation.GENERATE)
    mapped = _remap(result, tactic_id=identifier, support=SupportLevel.PARTIALLY_SUPPORTED)
    report = ENGINE.validate(mapped, package)
    assert report.is_valid


def test_citations_attached_to_a_mapping_are_still_validated():
    """F — widening the walk must not displace the citation checks it already ran."""
    result, package = result_for(ReasoningOperation.GENERATE)
    mapping = result.mappings[0]
    citation = dataclasses.replace(mapping.evidence[0], item_id="ctx-never-supplied")
    mapped = dataclasses.replace(
        result,
        mappings=(
            dataclasses.replace(mapping, evidence=(citation, *mapping.evidence[1:])),
            *result.mappings[1:],
        ),
    )
    report = ENGINE.validate(mapped, package)
    assert ValidationCode.UNKNOWN_ITEM in codes(report)
    assert any(issue.path == "mappings[0].evidence[0].item_id" for issue in report.errors)


def test_mapping_validation_is_deterministic():
    """G — the same faulty mapping produces the same report, in the same order."""
    result, package = result_for(ReasoningOperation.GENERATE)
    broken = _remap(
        result, tactic_id="TA9999", technique_id="T9999", support=SupportLevel.SUPPORTED
    )
    first = ENGINE.validate(broken, package)
    second = ENGINE.validate(broken, package)
    assert first == second
    assert first.issues == second.issues
    assert [i.sort_key for i in first.issues] == sorted(i.sort_key for i in first.issues)


# 17-18 — security


def test_a_credential_in_the_result_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    leaking = dataclasses.replace(
        result, summary="the rule embeds api_key=AIzaSyA1234567890123456789012345678901234"
    )
    report = ENGINE.validate(leaking, package)
    assert ValidationCode.CREDENTIAL_IN_RESULT in codes(report)
    assert report.of_category(ValidationCategory.SECURITY)


def test_a_prompt_template_artefact_in_the_result_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    echoed = dataclasses.replace(result, summary="the model echoed {{OUTPUT_FORMAT}} back")
    assert ValidationCode.TEMPLATE_ARTIFACT in codes(ENGINE.validate(echoed, package))


def test_a_fence_marker_in_the_result_is_rejected():
    from src.core.context_view import FENCE_END

    result, package = result_for(ReasoningOperation.ANALYZE)
    echoed = dataclasses.replace(result, summary=f"the rule said {FENCE_END} and then more")
    assert ValidationCode.FENCE_ARTIFACT in codes(ENGINE.validate(echoed, package))


def test_an_invented_external_reference_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    invented = dataclasses.replace(result, summary="see https://example.invalid/advisory/123")
    assert ValidationCode.FABRICATED_REFERENCE in codes(ENGINE.validate(invented, package))


# provenance


def test_a_citation_naming_the_wrong_source_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    mislabelled = dataclasses.replace(
        result,
        findings=(
            dataclasses.replace(
                result.findings[0],
                evidence=(
                    dataclasses.replace(
                        result.findings[0].evidence[0], source=EvidenceSource.SIGMA
                    ),
                ),
            ),
        ),
    )
    report = ENGINE.validate(mislabelled, package)
    assert ValidationCode.CITATION_SOURCE_MISMATCH in codes(report)
    assert report.of_category(ValidationCategory.PROVENANCE)


# 21-22 — determinism and edges


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_validation_is_deterministic(operation):
    result, package = result_for(operation)
    broken = dataclasses.replace(
        result,
        summary="leaked api_key=AIzaSyA1234567890123456789012345678901234\nsecond line",
        confidence=2.0,
    )
    first = ENGINE.validate(broken, package)
    second = ENGINE.validate(broken, package)
    assert first == second
    assert [i.sort_key for i in first.issues] == sorted(i.sort_key for i in first.issues)


def test_issue_order_is_stable_across_categories():
    result, package = result_for(ReasoningOperation.ANALYZE)
    broken = dataclasses.replace(
        result,
        confidence=5.0,
        summary="see https://example.invalid/x",
        uncertainties=(),
    )
    report = ENGINE.validate(broken, package)
    categories = [issue.category for issue in report.issues]
    assert categories == sorted(categories, key=lambda c: list(ValidationCategory).index(c))
    assert report.issue_count == len(report.errors) + len(report.warnings)


def test_a_result_with_nothing_in_it_is_still_judged():
    """An empty analyze result over an empty package: valid, and nothing invented."""
    package = ContextPackage(
        operation=ContextOperation.ANALYZE, rule_context=RuleContext(raw_text="title: x")
    )
    result, source_package = result_for(ReasoningOperation.ANALYZE)
    empty = dataclasses.replace(
        result, findings=(), recommendations=(), uncertainties=(), metadata={}
    )
    report = ENGINE.validate(empty, package)
    assert report.is_valid
    assert report.issue_count == 0


def test_an_empty_package_still_rejects_a_citation():
    package = ContextPackage(operation=ContextOperation.ANALYZE)
    result, _ = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(dataclasses.replace(result, uncertainties=()), package)
    assert ValidationCode.UNKNOWN_ITEM in codes(report)


# typed refusals


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda r: dataclasses.replace(r, confidence=9.0), StructuralValidationError),
        (
            lambda r: dataclasses.replace(
                r, findings=(dataclasses.replace(r.findings[0], evidence=()),)
            ),
            EvidenceValidationError,
        ),
        (lambda r: dataclasses.replace(r, uncertainties=()), UncertaintyValidationError),
        (
            lambda r: dataclasses.replace(r, summary="see https://example.invalid/x"),
            SecurityValidationError,
        ),
    ],
    ids=["structural", "evidence", "uncertainty", "security"],
)
def test_validate_or_raise_raises_the_typed_error_of_the_first_category(mutate, expected):
    result, package = result_for(ReasoningOperation.ANALYZE)
    with pytest.raises(expected) as error:
        ENGINE.validate_or_raise(mutate(result), package)
    assert error.value.report.issue_count >= 1
    assert error.value.issues


def test_severity_decides_whether_a_report_blocks():
    result, package = result_for(ReasoningOperation.GENERATE)
    warned = dataclasses.replace(
        result, generated_rule=dataclasses.replace(result.generated_rule, risk_score=95)
    )
    report = ENGINE.validate(warned, package)
    assert report.warnings
    assert not report.errors
    assert report.is_valid
    assert ENGINE.validate_or_raise(warned, package) is warned
    assert all(i.severity is IssueSeverity.WARNING for i in report.issues)


def _remap(result, *, tactic_id=None, technique_id=None, support=None):
    """Return the generate result with its first ATT&CK mapping claim altered.

    Built by replacement for the reason given on :func:`_recite`: Stage-15
    refuses a fabricated mapping at the parse boundary, and the point of these
    cases is a result that never passed through it.
    """
    mapping = result.mappings[0]
    if tactic_id is not None:
        mapping = dataclasses.replace(mapping, tactic_id=tactic_id)
    if technique_id is not None:
        mapping = dataclasses.replace(mapping, technique_id=technique_id)
    if support is not None:
        mapping = dataclasses.replace(mapping, support=support)
    return dataclasses.replace(result, mappings=(mapping, *result.mappings[1:]))


def _recite(result, *, item_id=None, identifier=None, support=None):
    """Return the result with its first citation altered.

    Built by replacement rather than by feeding a payload through Stage-15,
    because Stage-15 refuses these faults at the parse boundary. Stage-16 must
    still catch them: a result can reach this layer from a cache, an
    application, or a replayed log without ever passing through that boundary.
    """
    finding = result.findings[0]
    citation = finding.evidence[0]
    if item_id is not None:
        citation = dataclasses.replace(citation, item_id=item_id)
    if identifier is not None:
        citation = dataclasses.replace(citation, identifier=identifier)
    changed = dataclasses.replace(finding, evidence=(citation, *finding.evidence[1:]))
    if support is not None:
        changed = dataclasses.replace(changed, support=support)
    return dataclasses.replace(result, findings=(changed, *result.findings[1:]))
