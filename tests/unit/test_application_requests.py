"""Stage-18 request validation.

The request is the only input the pipeline accepts, and validating it is the
only chance to refuse a caller before any work is done. Two failure directions
matter equally: material an operation needs and did not get, and material an
operation has no field for and would therefore drop. The second is the one a
permissive validator lets through, so it is tested for every combination the
contract does not carry.
"""

from __future__ import annotations

import pytest

from src.application.requests import RULE_OPERATIONS, EngineRequest
from src.core.exceptions import InvalidReasoningRequestError
from src.core.types import ReasoningOperation

USER = "8a9ffc32-8495-4a25-a616-362d90f35dcc"
RULE = 'process.name:"powershell.exe"'
REQUIREMENT = "Detect encoded PowerShell command execution on Windows endpoints."
RULE_ID = "1bdc1065-5bd4-4dd6-a6df-c111d643ff90"

RULE_OPS = [ReasoningOperation.ANALYZE, ReasoningOperation.ENHANCE]


def analyze(**overrides) -> EngineRequest:
    """Return a valid analyze request, with the stated fields replaced."""
    fields = {"operation": ReasoningOperation.ANALYZE, "user_id": USER, "rule_text": RULE}
    return EngineRequest(**{**fields, **overrides})


def generate(**overrides) -> EngineRequest:
    """Return a valid generate request, with the stated fields replaced."""
    fields = {
        "operation": ReasoningOperation.GENERATE,
        "user_id": USER,
        "requirement": REQUIREMENT,
    }
    return EngineRequest(**{**fields, **overrides})


def test_rule_operations_are_analyze_and_enhance_only():
    assert RULE_OPERATIONS == frozenset(RULE_OPS)
    assert not generate().is_rule_operation


@pytest.mark.parametrize("operation", RULE_OPS, ids=lambda o: o.value)
def test_a_rule_operation_with_a_rule_and_a_user_is_valid(operation):
    analyze(operation=operation).validate()


@pytest.mark.parametrize("operation", RULE_OPS, ids=lambda o: o.value)
def test_a_rule_operation_may_name_a_saved_rule(operation):
    analyze(operation=operation, rule_id=RULE_ID).validate()


def test_a_generate_request_with_a_requirement_and_a_user_is_valid():
    generate().validate()


@pytest.mark.parametrize("blank", ["", "   ", "\n\t"])
@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_every_operation_needs_a_user(operation, blank):
    request = (
        generate(user_id=blank)
        if operation is ReasoningOperation.GENERATE
        else analyze(operation=operation, user_id=blank)
    )
    with pytest.raises(InvalidReasoningRequestError, match="user id"):
        request.validate()


@pytest.mark.parametrize("operation", RULE_OPS, ids=lambda o: o.value)
def test_a_rule_operation_without_a_rule_is_refused(operation):
    with pytest.raises(InvalidReasoningRequestError, match="needs a rule"):
        analyze(operation=operation, rule_text="   ").validate()


@pytest.mark.parametrize("operation", RULE_OPS, ids=lambda o: o.value)
def test_a_rule_operation_carrying_a_requirement_is_refused(operation):
    """The contract has nowhere to put it, so accepting it would discard it."""
    with pytest.raises(InvalidReasoningRequestError, match="discarded"):
        analyze(operation=operation, requirement=REQUIREMENT).validate()


def test_a_generate_request_without_a_requirement_is_refused():
    with pytest.raises(InvalidReasoningRequestError, match="detection requirement"):
        generate(requirement=" ").validate()


def test_a_generate_request_carrying_a_rule_is_refused():
    with pytest.raises(InvalidReasoningRequestError, match="discarded"):
        generate(rule_text=RULE).validate()


def test_a_generate_request_carrying_a_rule_id_is_refused():
    """The generate contract states no ruleId, so the value could only vanish."""
    with pytest.raises(InvalidReasoningRequestError, match="rule id"):
        generate(rule_id=RULE_ID).validate()


def test_a_generate_request_keeps_rule_id_optional_as_none():
    assert generate().rule_id is None


def test_the_request_is_frozen():
    request = analyze()
    with pytest.raises(AttributeError):
        request.rule_text = "other"
