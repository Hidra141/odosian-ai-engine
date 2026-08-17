"""Stage-15 reasoning validation.

The semantic half: uncertainty that must survive, citations that must point at
supplied material, and references that must hold inside the response.
"""

from __future__ import annotations

import copy
import dataclasses

import pytest

from src.context.types import ContextOperation
from src.core.exceptions import ReasoningValidationError
from src.core.models import ReasoningRequest
from src.core.response_parser import ResponseParser
from src.core.types import ReasoningOperation
from src.core.validation import ReasoningValidator
from tests.fixtures import stage15 as fixtures

PARSER = ResponseParser()
VALIDATOR = ReasoningValidator()


def _validate(payload, package=None, operation=ReasoningOperation.ANALYZE):
    package = package if package is not None else fixtures.context_package()
    request = ReasoningRequest(operation, package)
    response = fixtures.response_of(fixtures.body_of(payload))
    result = PARSER.parse(operation, response)
    return VALIDATOR.validate(result, request)


def checks(outcome):
    return [issue.check for issue in outcome.issues]


def test_a_valid_response_passes_every_check():
    package = fixtures.context_package()
    outcome = _validate(fixtures.analyze_response(package), package)
    assert outcome.issues == ()
    assert outcome.is_valid


def test_dropping_an_unresolved_identifier_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["uncertainties"] = [
        entry for entry in payload["uncertainties"] if entry["identifier"] != "T1562"
    ]
    assert "uncertainty_dropped" in checks(_validate(payload, package))


def test_declaring_an_unresolved_identifier_resolved_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    for entry in payload["uncertainties"]:
        if entry["identifier"] == "T1562":
            entry["status"] = "ambiguous"
    assert "uncertainty_status_changed" in checks(_validate(payload, package))


def test_narrowing_an_ambiguous_identifier_to_one_candidate_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    for entry in payload["uncertainties"]:
        if entry["identifier"] == "M1013":
            entry["candidates"] = ["enterprise:M1013"]
    outcome = _validate(payload, package)
    assert "ambiguity_narrowed" in checks(outcome)
    assert "mobile:M1013" in str(outcome.issues[0])


def test_inventing_a_candidate_for_an_ambiguous_identifier_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    for entry in payload["uncertainties"]:
        if entry["identifier"] == "M1013":
            entry["candidates"] = ["enterprise:M1013", "mobile:M1013", "ics:M1013"]
    assert "fabricated_candidate" in checks(_validate(payload, package))


def test_reporting_an_uncertainty_the_context_never_raised_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["uncertainties"].append(
        {
            "identifier": "T9999",
            "status": "unresolved",
            "candidates": [],
            "treatment": "invented",
        }
    )
    assert "fabricated_uncertainty" in checks(_validate(payload, package))


def test_resting_a_supported_claim_on_an_unsettled_identifier_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["findings"][0]["evidence"][0]["identifier"] = "M1013"
    payload["findings"][0]["support"] = "supported"
    assert "uncertainty_presented_as_fact" in checks(_validate(payload, package))


def test_citing_an_item_the_package_does_not_carry_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["findings"][0]["evidence"][0]["item_id"] = "retrieval:9999"
    assert "fabricated_reference" in checks(_validate(payload, package))


def test_stating_an_identifier_the_material_does_not_contain_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["findings"][0]["evidence"][0]["identifier"] = "T1218.011"
    assert "fabricated_identifier" in checks(_validate(payload, package))


def test_addressing_a_finding_that_does_not_exist_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["recommendations"][0]["addresses"] = ["F9"]
    assert "unknown_finding_reference" in checks(_validate(payload, package))


def test_reusing_a_finding_id_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["findings"].append(copy.deepcopy(payload["findings"][0]))
    assert "duplicate_finding_id" in checks(_validate(payload, package))


def test_answering_a_different_operation_is_rejected_by_the_schema():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["operation"] = "enhance"
    with pytest.raises(Exception) as error:
        _validate(payload, package)
    assert "operation" in str(error.value)


def test_an_enhanced_rule_must_reproduce_the_original_query():
    package = fixtures.context_package(ContextOperation.ENHANCE)
    payload = fixtures.enhance_response(package)
    payload["original_rule"]["query"] = "process.name:cmd.exe"
    outcome = _validate(payload, package, ReasoningOperation.ENHANCE)
    assert "original_rule_altered" in checks(outcome)


def test_an_enhanced_rule_identical_to_the_original_is_rejected():
    package = fixtures.context_package(ContextOperation.ENHANCE)
    payload = fixtures.enhance_response(package)
    payload["enhanced_rule"]["query"] = fixtures.RULE_QUERY
    assert "rule_unchanged" in checks(_validate(payload, package, ReasoningOperation.ENHANCE))


# the original query, compared across the ways one query can be written


REAL_MULTI_LINE_QUERY = (
    "event.category:(network or network_traffic) and network.transport:tcp and\n"
    "  source.ip:(\n"
    "    10.0.0.0/8 or\n"
    "    172.16.0.0/12 or\n"
    "    192.168.0.0/16\n"
    "  )"
)
"""The shape a real Elastic rule states its query in, indented across lines."""

REAL_FLATTENED_QUERY = (
    "event.category:(network or network_traffic) and network.transport:tcp and "
    "source.ip:(10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)"
)
"""The same query as a model repeated it back: one line, no padding.

Taken from a real ``gemini-3.5-flash`` enhancement of Elastic rule
``87ec6396-9ac4-4706-bcf0-2ebb22002f43``. Collapsing the indentation alone
leaves ``( 10.0.0.0/8 … )``, while the model wrote ``(10.0.0.0/8 …)``, and the
two were held to be different queries.
"""


def enhance_with_queries(original: str, supplied: str, enhanced: str | None = None):
    """Return the outcome of validating one enhancement of a stated query."""
    rule = dataclasses.replace(fixtures.rule_context(), query=supplied)
    package = fixtures.context_package(ContextOperation.ENHANCE, rule=rule)
    payload = fixtures.enhance_response(package)
    payload["original_rule"]["query"] = original
    if enhanced is not None:
        payload["enhanced_rule"]["query"] = enhanced
    return _validate(payload, package, ReasoningOperation.ENHANCE)


def test_the_real_flattened_query_reproduces_the_multi_line_original():
    """The exact comparison that failed against the live model."""
    outcome = enhance_with_queries(REAL_FLATTENED_QUERY, REAL_MULTI_LINE_QUERY)
    assert "original_rule_altered" not in checks(outcome)


def test_padding_inside_parentheses_is_not_a_change():
    outcome = enhance_with_queries(
        "process.name:(powershell.exe)", "process.name:( powershell.exe )"
    )
    assert "original_rule_altered" not in checks(outcome)


def test_padding_added_rather_than_removed_is_not_a_change_either():
    outcome = enhance_with_queries(
        "process.name:( powershell.exe )", "process.name:(powershell.exe)"
    )
    assert "original_rule_altered" not in checks(outcome)


def test_a_query_flattened_onto_one_line_is_not_a_change():
    outcome = enhance_with_queries(
        "process.name:powershell.exe or process.name:cmd.exe",
        "process.name:powershell.exe or\n  process.name:cmd.exe",
    )
    assert "original_rule_altered" not in checks(outcome)


@pytest.mark.parametrize(
    ("original", "supplied"),
    [
        ("process.name:cmd.exe", "process.name:powershell.exe"),
        ("process.name:(cmd.exe)", "process.name:(powershell.exe)"),
        ("process.name:(a or b)", "process.name:(a or c)"),
        ("process.name:a and process.args:b", "process.name:a or process.args:b"),
        ("process.name:(a)", "process.name:(a or b)"),
        ('process.command_line:"a (b)"', 'process.command_line:"a ( b )"'),
    ],
)
def test_a_genuinely_different_query_is_still_rejected(original, supplied):
    """Padding is insignificant between terms and significant inside a literal."""
    outcome = enhance_with_queries(original, supplied)
    assert "original_rule_altered" in checks(outcome)


def test_a_term_separating_space_is_never_removed():
    """Collapsing 'a or b' into 'a orb' would be a different query, not a format."""
    outcome = enhance_with_queries("process.name:(a orb)", "process.name:(a or b)")
    assert "original_rule_altered" in checks(outcome)


def test_reformatting_the_query_alone_still_counts_as_no_rewrite():
    """An enhancement that only re-spaces the original has not rewritten it."""
    outcome = enhance_with_queries(
        REAL_FLATTENED_QUERY, REAL_MULTI_LINE_QUERY, enhanced=REAL_FLATTENED_QUERY
    )
    assert "rule_unchanged" in checks(outcome)


def _mitre(technique_id: str) -> dict[str, object]:
    """Return a schema-complete rule mapping naming one technique.

    The names stay empty: these cases are about the identifier, and a name the
    supplied material never carried is exactly what must not be written.
    """
    return {
        "tactic_id": "",
        "tactic_name": "",
        "technique_id": technique_id,
        "technique_name": "",
        "confidence": 0.5,
        "parent_technique_id": "",
        "parent_technique_name": "",
    }


def test_a_produced_rule_may_not_map_to_an_unsettled_identifier():
    package = fixtures.context_package(ContextOperation.ENHANCE)
    payload = fixtures.enhance_response(package)
    payload["enhanced_rule"]["mitre"] = [_mitre("T1562")]
    assert "unsettled_identifier_in_rule" in checks(
        _validate(payload, package, ReasoningOperation.ENHANCE)
    )


def test_a_produced_rule_may_not_map_to_an_identifier_that_was_never_supplied():
    package = fixtures.context_package(ContextOperation.ENHANCE)
    payload = fixtures.enhance_response(package)
    payload["enhanced_rule"]["mitre"] = [_mitre("T1055.012")]
    assert "fabricated_identifier" in checks(
        _validate(payload, package, ReasoningOperation.ENHANCE)
    )


def test_invalid_results_raise_a_typed_error_listing_every_issue():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["findings"][0]["evidence"][0]["item_id"] = "retrieval:9999"
    payload["recommendations"][0]["addresses"] = ["F9"]
    outcome = _validate(payload, package)
    with pytest.raises(ReasoningValidationError) as error:
        outcome.raise_if_invalid()
    assert len(error.value.issues) == 2
    assert error.value.operation == "analyze"


def test_a_generate_result_keeps_its_uncertainties():
    package = fixtures.context_package(ContextOperation.GENERATE)
    outcome = _validate(
        fixtures.generate_response(package), package, ReasoningOperation.GENERATE
    )
    assert outcome.is_valid
