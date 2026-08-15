"""Identifier boundaries at the validation boundary.

An identifier is supplied or it is not. Plain containment blurred that: material
carrying ``T1059.001`` also "supplied" ``T105``, ``T10`` and ``T1``, so a result
could assert a technique nobody named by standing close enough to one that was.
The anti-fabrication check said yes to identifiers that do not exist.

These cases fix the boundary in place — first on the matcher itself, then
through the engine on each of the three places a mapping can sit, because a
matcher that is right in isolation is worth nothing if a checker reaches its
identifiers by another route.
"""

from __future__ import annotations

import dataclasses

import pytest

from src.context.types import ContextOperation
from src.core.identifiers import occurs_as_identifier
from src.core.models import (
    AnalyzeRequest,
    EnhanceRequest,
    GenerateRequest,
    MitreMapping,
)
from src.core.types import ReasoningOperation
from src.validation import ValidationCode, ValidationEngine
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

SUPPLIED = "T1059.001"
"""The one technique the fixture package actually supplies."""


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


def remitre(result, field, **changes):
    """Return the result with its produced rule's first ATT&CK mapping altered."""
    rule = getattr(result, field)
    mapping = dataclasses.replace(
        MitreMapping(tactic_id="", technique_id=SUPPLIED, confidence=0.5), **changes
    )
    return dataclasses.replace(
        result, **{field: dataclasses.replace(rule, mitre=(mapping,))}
    )


# the matcher itself


@pytest.mark.parametrize(
    ("identifier", "text", "expected"),
    [
        ("T1059.001", "the record covers T1059.001 here", True),
        ("T1059", "the record covers T1059 here", True),
        ("TA0011", "TA0011: unresolved", True),
        ("M1013", "M1013: ambiguous", True),
        ("process.command_line", "matches process.command_line only", True),
    ],
    ids=["sub-technique", "technique", "tactic", "mitigation", "ecs-field"],
)
def test_an_identifier_present_in_full_is_supplied(identifier, text, expected):
    assert occurs_as_identifier(identifier, text) is expected


@pytest.mark.parametrize(
    "identifier",
    ["T105", "T10", "T1", "T1059", "1059", "001", "059.001"],
)
def test_no_fragment_of_a_sub_technique_is_supplied_by_it(identifier):
    """The original defect: a piece of T1059.001 is not an identifier."""
    assert occurs_as_identifier(identifier, "evidence for T1059.001 only") is False


@pytest.mark.parametrize("identifier", ["TA001", "TA0", "TA00", "0011"])
def test_no_fragment_of_a_tactic_is_supplied_by_it(identifier):
    assert occurs_as_identifier(identifier, "TA0011 was not resolved") is False


def test_a_parent_technique_is_supplied_when_it_stands_alone():
    """Independently present, so genuinely supplied — this must keep working."""
    assert occurs_as_identifier("T1059", "T1059 and T1059.001 are both named") is True


def test_a_longer_sub_technique_does_not_supply_a_shorter_one():
    assert occurs_as_identifier("T1059.001", "only T1059.0011 appears") is False


@pytest.mark.parametrize(
    "text",
    [
        "(T1059.001)",
        "[T1059.001]",
        "see T1059.001.",
        "T1059.001, and more",
        "id=T1059.001;next",
        "'T1059.001'",
        "T1059.001\nnext line",
        "technique:T1059.001",
    ],
)
def test_punctuation_around_an_identifier_does_not_break_the_match(text):
    assert occurs_as_identifier("T1059.001", text) is True


def test_matching_is_case_sensitive_as_the_identifier_policy_requires():
    assert occurs_as_identifier("t1059.001", "T1059.001") is False
    assert occurs_as_identifier("T1059.001", "t1059.001") is False


def test_several_identifiers_in_one_body_are_each_found_independently():
    text = "T1059.001 with TA0011 and M1013 and T1562"
    assert all(
        occurs_as_identifier(value, text)
        for value in ("T1059.001", "TA0011", "M1013", "T1562")
    )
    assert not any(
        occurs_as_identifier(value, text) for value in ("T105", "TA001", "M101", "T156")
    )


def test_matching_is_deterministic():
    text = "T1059.001 appears, then T1059.001 appears again"
    assert [occurs_as_identifier("T1059.001", text) for _ in range(5)] == [True] * 5
    assert [occurs_as_identifier("T105", text) for _ in range(5)] == [False] * 5


def test_an_empty_identifier_is_never_supplied():
    assert occurs_as_identifier("", "T1059.001") is False


# through the engine — analyze mappings


def test_an_analyze_mapping_naming_the_supplied_technique_is_accepted():
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert ENGINE.validate(remap(result, technique_id=SUPPLIED), package).is_valid


@pytest.mark.parametrize("identifier", ["T105", "T10", "T1"])
def test_an_analyze_mapping_claiming_a_fragment_is_rejected(identifier):
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, technique_id=identifier), package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert [i.path for i in report.errors] == ["mappings[0].technique_id"]


def test_a_parent_technique_the_package_names_elsewhere_is_still_accepted():
    """T1059 is supplied here — the reference URL names it, ending at the slash.

    Worth pinning rather than assuming. The boundary rule must reject a fragment
    of a longer identifier without rejecting an identifier that genuinely occurs
    somewhere else in the material, and here both are true of the same package.
    """
    result, package = result_for(ReasoningOperation.ANALYZE)
    assert "/techniques/T1059/001/" in "\n".join(item.text for item in package.items)
    assert ENGINE.validate(remap(result, technique_id="T1059"), package).is_valid


def test_an_analyze_mapping_claiming_a_tactic_fragment_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    report = ENGINE.validate(remap(result, tactic_id="TA001"), package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert [i.path for i in report.errors] == ["mappings[0].tactic_id"]


# through the engine — generate mappings


def test_a_generate_mapping_naming_the_supplied_technique_is_accepted():
    result, package = result_for(ReasoningOperation.GENERATE)
    assert ENGINE.validate(remap(result, technique_id=SUPPLIED), package).is_valid


@pytest.mark.parametrize("identifier", ["T105", "T10"])
def test_a_generate_mapping_claiming_a_fragment_is_rejected(identifier):
    result, package = result_for(ReasoningOperation.GENERATE)
    report = ENGINE.validate(remap(result, technique_id=identifier), package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)


# through the engine — a produced rule's own ATT&CK mapping


@pytest.mark.parametrize(
    ("operation", "field"),
    [
        (ReasoningOperation.ENHANCE, "enhanced_rule"),
        (ReasoningOperation.GENERATE, "generated_rule"),
    ],
    ids=["enhanced", "generated"],
)
def test_a_rule_mapping_naming_the_supplied_technique_is_accepted(operation, field):
    result, package = result_for(operation)
    assert ENGINE.validate(remitre(result, field), package).is_valid


@pytest.mark.parametrize(
    ("operation", "field"),
    [
        (ReasoningOperation.ENHANCE, "enhanced_rule"),
        (ReasoningOperation.GENERATE, "generated_rule"),
    ],
    ids=["enhanced", "generated"],
)
@pytest.mark.parametrize("identifier", ["T105", "T10"])
def test_a_rule_mapping_claiming_a_fragment_is_rejected(operation, field, identifier):
    result, package = result_for(operation)
    report = ENGINE.validate(remitre(result, field, technique_id=identifier), package)
    assert ValidationCode.FABRICATED_MAPPING in codes(report)
    assert any(i.path == f"{field}.mitre[0].technique_id" for i in report.errors)


# through the engine — identifiers asserted inside grounded free text


@pytest.mark.parametrize("identifier", ["T1562.001", "T1059.002"])
def test_a_strength_asserting_a_neighbouring_identifier_is_rejected(identifier):
    """The material names T1562 and T1059.001; neither supplies these."""
    result, package = result_for(ReasoningOperation.ANALYZE)
    claimed = dataclasses.replace(result, strengths=(f"Covers {identifier} well.",))
    report = ENGINE.validate(claimed, package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "strengths[0]" for i in report.errors)


@pytest.mark.parametrize("fragment", ["T105", "TA001", "T10"])
def test_a_malformed_fragment_in_prose_is_not_read_as_an_identifier(fragment):
    """Prose is scanned for well-formed identifiers only.

    ``T105`` is not an ATT&CK identifier in any corpus, so it asserts nothing
    about one. Treating every digit-bearing token as a claim would reject
    ordinary sentences; the guarantee is over identifiers, and this is not one.
    """
    result, package = result_for(ReasoningOperation.ANALYZE)
    claimed = dataclasses.replace(result, strengths=(f"Mentions {fragment} in passing.",))
    assert ENGINE.validate(claimed, package).is_valid


def test_a_strength_naming_the_supplied_technique_in_full_is_accepted():
    result, package = result_for(ReasoningOperation.ANALYZE)
    claimed = dataclasses.replace(
        result, strengths=(f"Covers {SUPPLIED} as the material describes it.",)
    )
    assert ENGINE.validate(claimed, package).is_valid


def test_a_code_snippet_asserting_a_fragment_is_rejected():
    result, package = result_for(ReasoningOperation.ANALYZE)
    first = dataclasses.replace(
        result.recommendations[0], code_snippet="threat.technique.id:'T1562.001'"
    )
    claimed = dataclasses.replace(
        result, recommendations=(first, *result.recommendations[1:])
    )
    report = ENGINE.validate(claimed, package)
    assert ValidationCode.FABRICATED_IDENTIFIER in codes(report)
    assert any(i.path == "recommendations[0].code_snippet" for i in report.errors)


# nothing that was already accepted stopped being accepted


@pytest.mark.parametrize("operation", list(BUILDERS), ids=lambda o: o.value)
def test_the_faithful_fixture_result_is_still_accepted(operation):
    result, package = result_for(operation)
    assert ENGINE.validate(result, package).is_valid


@pytest.mark.parametrize("identifier", ["T1562", "TA0011", "M1013"])
def test_the_unsettled_identifiers_are_still_recognised_as_supplied(identifier):
    """They are supplied and unsettled. Boundary matching must not hide either."""
    _, package = result_for(ReasoningOperation.ANALYZE)
    from src.validation import SuppliedContext

    supplied = SuppliedContext.of(package)
    assert supplied.supplies(identifier)
    assert supplied.is_unsettled(identifier)
