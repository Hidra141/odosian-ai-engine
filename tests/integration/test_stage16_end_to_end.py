"""Stage-16 end to end.

A real Sigma rule through the real Stage-08, Stage-09, Stage-10 and Stage-14
objects, into the Stage-15 engine over a fake provider, and out through the
Stage-16 validation boundary.

Retrieval is supplied as a fixture rather than run, so no test here reads a
dataset. Everything else on the path is the shipped code, and no provider is
called: the three named cases — PowerShell/T1059.001, unresolved T1562 and
ambiguous M1013 — arrive in the package exactly as Stage-13 would report them.
"""

from __future__ import annotations

import dataclasses

import pytest

from src.context.context_builder import ContextBuilder
from src.context.types import ContextOperation, EvidenceStatus
from src.context.validation import ContextValidator
from src.core.models import AnalyzeRequest, EnhanceRequest, GenerateRequest, MitreMapping
from src.core.types import ReasoningOperation, UncertaintyStatus
from src.entities.extractor import EntityExtractor
from src.mapping.entity_mapper import EntityMapper
from src.parser.parser import RuleParser
from src.validation import (
    RuleIntegrityValidationError,
    UncertaintyValidationError,
    ValidationCode,
    ValidationEngine,
)
from tests.fixtures import stage15 as fixtures

ENGINE = ValidationEngine()

CALLS = {
    ContextOperation.ANALYZE: (fixtures.analyze_response, "analyze", AnalyzeRequest),
    ContextOperation.ENHANCE: (fixtures.enhance_response, "enhance", EnhanceRequest),
    ContextOperation.GENERATE: (fixtures.generate_response, "generate", GenerateRequest),
}


def pipeline(operation: ContextOperation = ContextOperation.ANALYZE):
    """Run the frozen stages, then Stage-15, and return both ends."""
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
    return getattr(engine, call)(request_of(package=package)), package


# A — PowerShell / T1059.001


def test_a_supported_result_is_accepted_end_to_end():
    result, package = pipeline()
    report = ENGINE.validate(result, package)
    assert report.is_valid
    assert report.issue_count == 0
    assert ENGINE.validate_or_raise(result, package) is result
    assert result.findings[0].evidence[0].identifier == "T1059.001"


@pytest.mark.parametrize("operation", list(CALLS), ids=lambda o: o.value)
def test_every_operation_passes_the_boundary(operation):
    result, package = pipeline(operation)
    assert ENGINE.validate(result, package).is_valid
    assert set(result.cited_item_ids()) <= {item.item_id for item in package.items}


# B — T1562 unresolved


def test_t1562_remains_unresolved_through_the_boundary():
    result, package = pipeline()
    carried = {entry.identifier: entry for entry in result.uncertainties}
    assert carried["T1562"].status is UncertaintyStatus.UNRESOLVED
    assert carried["T1562"].candidates == ()
    assert any(
        item.evidence_status is EvidenceStatus.UNRESOLVED for item in package.unresolved_items
    )
    assert ENGINE.validate(result, package).is_valid


def test_dropping_t1562_is_refused_at_the_boundary():
    result, package = pipeline()
    kept = tuple(e for e in result.uncertainties if e.identifier != "T1562")
    with pytest.raises(UncertaintyValidationError) as error:
        ENGINE.validate_or_raise(dataclasses.replace(result, uncertainties=kept), package)
    assert error.value.report.codes()[0] is ValidationCode.UNCERTAINTY_DROPPED
    assert "T1562" in error.value.issues[0]


def test_ta0011_remains_unresolved_through_the_boundary():
    result, package = pipeline()
    carried = {entry.identifier: entry for entry in result.uncertainties}
    assert carried["TA0011"].status is UncertaintyStatus.UNRESOLVED
    promoted = tuple(
        dataclasses.replace(e, status=UncertaintyStatus.AMBIGUOUS, candidates=("guess",))
        if e.identifier == "TA0011"
        else e
        for e in result.uncertainties
    )
    report = ENGINE.validate(dataclasses.replace(result, uncertainties=promoted), package)
    assert ValidationCode.UNCERTAINTY_STATUS_PROMOTED in report.codes()


# C — M1013 ambiguous


def test_m1013_keeps_both_candidates_through_the_boundary():
    result, package = pipeline()
    carried = {entry.identifier: entry for entry in result.uncertainties}
    assert carried["M1013"].status is UncertaintyStatus.AMBIGUOUS
    assert carried["M1013"].candidates == ("enterprise:M1013", "mobile:M1013")
    assert ENGINE.validate(result, package).is_valid


def test_narrowing_m1013_to_one_candidate_is_refused():
    result, package = pipeline()
    narrowed = tuple(
        dataclasses.replace(e, candidates=(e.candidates[0],)) if e.identifier == "M1013" else e
        for e in result.uncertainties
    )
    with pytest.raises(UncertaintyValidationError) as error:
        ENGINE.validate_or_raise(dataclasses.replace(result, uncertainties=narrowed), package)
    assert "mobile:M1013" in error.value.issues[0]


# the live fabrication, reproduced


def test_the_live_ta0002_fabrication_is_refused():
    """The tactic the model invented on the live enhance call, caught again here."""
    result, package = pipeline(ContextOperation.ENHANCE)
    assert "TA0002" not in "\n".join(item.text for item in package.items)
    fabricated = dataclasses.replace(
        result.enhanced_rule,
        mitre=(MitreMapping(tactic_id="TA0002", technique_id="T1059.001"),),
    )
    with pytest.raises(RuleIntegrityValidationError) as error:
        ENGINE.validate_or_raise(
            dataclasses.replace(result, enhanced_rule=fabricated), package
        )
    assert error.value.report.codes()[0] is ValidationCode.FABRICATED_MAPPING
    assert "TA0002" in error.value.issues[0]


# determinism and immutability


def test_validation_is_deterministic_over_the_real_pipeline():
    result, package = pipeline()
    assert ENGINE.validate(result, package) == ENGINE.validate(result, package)

    other_result, other_package = pipeline()
    assert ENGINE.validate(other_result, other_package) == ENGINE.validate(result, package)


def test_validation_mutates_neither_input():
    result, package = pipeline()
    before_result = dataclasses.replace(result)
    before_items = tuple(item.item_id for item in package.items)
    before_warnings = tuple(str(w) for w in package.warnings)

    ENGINE.validate(result, package)

    assert result == before_result
    assert tuple(item.item_id for item in package.items) == before_items
    assert tuple(str(w) for w in package.warnings) == before_warnings


def test_the_boundary_accepts_the_operation_the_package_was_built_for():
    result, package = pipeline(ContextOperation.GENERATE)
    report = ENGINE.validate(result, package)
    assert report.operation is ReasoningOperation.GENERATE
    assert report.is_valid


# the Stage-15 accessor regression stays fixed


@pytest.mark.parametrize("operation", list(CALLS), ids=lambda o: o.value)
def test_cited_item_ids_still_works_on_every_result_type(operation):
    result, package = pipeline(operation)
    cited = result.cited_item_ids()
    assert cited == tuple(dict.fromkeys(cited))
    assert set(cited) <= {item.item_id for item in package.items}
