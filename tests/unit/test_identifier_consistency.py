"""One identifier rule, two validation layers.

Stage-15 judges the response it has just parsed; Stage-16 judges whatever
reaches the acceptance boundary. Both ask whether the supplied material carried
an identifier, and for a while they answered differently: Stage-16 matched on
identifier boundaries while Stage-15 still matched on plain containment, so
material naming ``T1059.001`` supplied ``T105`` to one layer and not to the
other.

A guarantee that depends on which layer looked is not a guarantee. These cases
hold the two to the same answer.
"""

from __future__ import annotations

import pytest

from src.context.types import ContextOperation
from src.core.identifiers import occurs_as_identifier
from src.core.models import ReasoningRequest
from src.core.response_parser import ResponseParser
from src.core.types import ReasoningOperation
from src.core.validation import ReasoningValidator, SuppliedMaterial
from src.validation import SuppliedContext
from tests.fixtures import stage15 as fixtures

PARSER = ResponseParser()
VALIDATOR = ReasoningValidator()

SUPPLIED = "T1059.001"
"""The sub-technique the fixture package supplies."""

FRAGMENTS = ["T105", "T10", "T1", "TA001", "T1059.0011"]
"""Pieces of, or near-misses on, identifiers the package really carries."""


def stage15_material(package, rule_text: str = ""):
    """Return Stage-15's view of what the package supplied."""
    return SuppliedMaterial.of(package, rule_text)


def stage16_supplied(package):
    """Return Stage-16's view of what the package supplied."""
    return SuppliedContext.of(package)


def validate_stage15(payload, package, operation):
    """Run Stage-15's own validator over a response payload."""
    request = ReasoningRequest(operation, package)
    response = fixtures.response_of(fixtures.body_of(payload))
    result = PARSER.parse(operation, response)
    return VALIDATOR.validate(result, request)


def stage15_checks(outcome):
    return [issue.check for issue in outcome.issues]


# 1 — Stage-15 matches an identifier exactly


@pytest.mark.parametrize("identifier", [SUPPLIED, "T1562", "TA0011", "M1013"])
def test_stage15_still_accepts_an_identifier_the_material_carries(identifier):
    package = fixtures.context_package()
    assert stage15_material(package).supplies(identifier)


# 2 — Stage-15 rejects fragments


@pytest.mark.parametrize("fragment", FRAGMENTS)
def test_stage15_no_longer_accepts_a_fragment(fragment):
    package = fixtures.context_package()
    assert not stage15_material(package).supplies(fragment)


def test_stage15_rejects_a_fabricated_fragment_in_a_produced_rule():
    """End to end through Stage-15's own validator, not just the matcher."""
    package = fixtures.context_package(ContextOperation.ENHANCE)
    payload = fixtures.enhance_response(package)
    payload["enhanced_rule"]["mitre"] = [
        {
            "tactic_id": "",
            "tactic_name": "",
            "technique_id": "T105",
            "technique_name": "",
            "confidence": 0.5,
        }
    ]
    outcome = validate_stage15(payload, package, ReasoningOperation.ENHANCE)
    assert "fabricated_identifier" in stage15_checks(outcome)


def test_stage15_rejects_a_fabricated_fragment_in_a_mapping_claim():
    package = fixtures.context_package(ContextOperation.GENERATE)
    payload = fixtures.generate_response(package)
    payload["mappings"][0]["technique_id"] = "T105"
    outcome = validate_stage15(payload, package, ReasoningOperation.GENERATE)
    assert "fabricated_identifier" in stage15_checks(outcome)


def test_stage15_rejects_a_fabricated_fragment_in_a_citation():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["findings"][0]["evidence"][0]["identifier"] = "T105"
    outcome = validate_stage15(payload, package, ReasoningOperation.ANALYZE)
    assert "fabricated_identifier" in stage15_checks(outcome)


# 3, 4 — the two layers agree


@pytest.mark.parametrize(
    "identifier",
    [SUPPLIED, "T1562", "TA0011", "M1013", *FRAGMENTS, "", "T9999", "TA9999"],
)
@pytest.mark.parametrize(
    "context_operation",
    list(ContextOperation),
    ids=lambda o: o.value,
)
def test_both_layers_answer_the_same_for_the_same_identifier(
    identifier, context_operation
):
    package = fixtures.context_package(context_operation)
    assert stage15_material(package).supplies(identifier) is stage16_supplied(
        package
    ).supplies(identifier)


@pytest.mark.parametrize("fragment", FRAGMENTS)
def test_neither_layer_accepts_a_fragment(fragment):
    package = fixtures.context_package()
    assert not stage15_material(package).supplies(fragment)
    assert not stage16_supplied(package).supplies(fragment)


def test_both_layers_route_through_the_one_shared_rule():
    """Not merely agreeing by coincidence — the same function decides both."""
    package = fixtures.context_package()
    material = stage15_material(package)
    supplied = stage16_supplied(package)
    for identifier in (SUPPLIED, *FRAGMENTS, "T1562"):
        expected = occurs_as_identifier(identifier, material.text)
        assert material.supplies(identifier) is expected
        assert supplied.supplies(identifier) is occurs_as_identifier(
            identifier, supplied.text
        )


# 5 — nothing that was valid stopped being valid


@pytest.mark.parametrize(
    ("operation", "context_operation", "response_of"),
    [
        (ReasoningOperation.ANALYZE, ContextOperation.ANALYZE, fixtures.analyze_response),
        (ReasoningOperation.ENHANCE, ContextOperation.ENHANCE, fixtures.enhance_response),
        (
            ReasoningOperation.GENERATE,
            ContextOperation.GENERATE,
            fixtures.generate_response,
        ),
    ],
    ids=["analyze", "enhance", "generate"],
)
def test_a_faithful_response_still_passes_stage15(
    operation, context_operation, response_of
):
    package = fixtures.context_package(context_operation)
    outcome = validate_stage15(response_of(package), package, operation)
    assert outcome.issues == ()
    assert outcome.is_valid


def test_a_parent_technique_the_package_names_elsewhere_is_accepted_by_both():
    """T1059 is supplied here by the reference URL, and both layers must see it."""
    package = fixtures.context_package()
    assert "/techniques/T1059/001/" in "\n".join(item.text for item in package.items)
    assert stage15_material(package).supplies("T1059")
    assert stage16_supplied(package).supplies("T1059")
