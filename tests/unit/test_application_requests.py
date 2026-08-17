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

from src.application.requests import (
    QUERY_LANGUAGES,
    QUERY_OPERATIONS,
    RULE_OPERATIONS,
    EngineRequest,
)
from src.core.exceptions import InvalidReasoningRequestError
from src.core.types import ReasoningOperation
from src.parser.types import RuleLanguage

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


# --------------------------------------------------------------------------- raw query


RAW_QUERY = 'process.name:"powershell.exe" and process.command_line:*-enc*'


def raw(**overrides) -> EngineRequest:
    """Return a valid raw-query analyze request, with the stated fields replaced."""
    fields = {
        "operation": ReasoningOperation.ANALYZE,
        "user_id": USER,
        "query": RAW_QUERY,
        "language": "kuery",
    }
    return EngineRequest(**{**fields, **overrides})


def test_query_operations_are_analyze_only():
    assert QUERY_OPERATIONS == frozenset({ReasoningOperation.ANALYZE})


def test_the_supported_query_languages_are_the_four_the_contract_states():
    assert {item.value for item in QUERY_LANGUAGES} == {"kuery", "eql", "lucene", "esql"}
    assert RuleLanguage.SIGMA not in QUERY_LANGUAGES


def test_an_analyze_request_stating_a_query_and_a_language_is_valid():
    raw().validate()


@pytest.mark.parametrize("token", ["kuery", "kql", "eql", "lucene", "esql", "es|ql", "ESQL"])
def test_every_spelling_stage_eight_accepts_is_accepted_here(token):
    raw(language=token).validate()


def test_a_request_stating_a_query_reports_itself_as_one():
    assert raw().is_raw_query
    assert not analyze().is_raw_query


def test_the_stated_language_reaches_stage_eight_vocabulary():
    assert raw(language="kql").rule_language is RuleLanguage.KUERY
    assert raw(language="es|ql").rule_language is RuleLanguage.ESQL


@pytest.mark.parametrize("token", ["sigma", "spl", "sql", "yara", "", "   "])
def test_a_language_the_engine_cannot_read_is_refused(token):
    with pytest.raises(InvalidReasoningRequestError):
        raw(language=token).validate()


def test_a_query_without_a_language_is_refused():
    with pytest.raises(InvalidReasoningRequestError, match="language"):
        raw(language="").validate()


def test_an_unsupported_language_names_what_is_supported():
    with pytest.raises(InvalidReasoningRequestError, match="kuery"):
        raw(language="spl").validate()


def test_a_rule_and_a_query_together_are_refused():
    """Two subjects state neither."""
    with pytest.raises(InvalidReasoningRequestError, match="both"):
        raw(rule_text=RULE).validate()


def test_a_structured_rule_carrying_a_language_is_refused():
    """The rule states its own, so the one beside it could only be discarded."""
    with pytest.raises(InvalidReasoningRequestError, match="discarded"):
        analyze(language="kuery").validate()


def test_an_analyze_request_with_neither_subject_is_refused():
    with pytest.raises(InvalidReasoningRequestError, match="needs a rule"):
        analyze(rule_text="").validate()


def test_enhance_refuses_a_raw_query():
    """Enhance reports the original rule beside the rewrite, so it needs the rule."""
    with pytest.raises(InvalidReasoningRequestError, match="bare query"):
        raw(operation=ReasoningOperation.ENHANCE).validate()


def test_generate_refuses_a_raw_query():
    with pytest.raises(InvalidReasoningRequestError, match="discarded"):
        generate(query=RAW_QUERY).validate()


def test_generate_refuses_a_language():
    """Generate chooses the language of the rule it writes."""
    with pytest.raises(InvalidReasoningRequestError, match="discarded"):
        generate(language="kuery").validate()


def test_a_raw_query_may_be_ad_hoc_with_no_rule_id():
    assert raw().rule_id is None
    raw().validate()


def test_a_raw_query_analysis_may_still_name_a_saved_rule():
    raw(rule_id=RULE_ID).validate()


def test_every_operation_still_needs_a_user_when_stating_a_query():
    with pytest.raises(InvalidReasoningRequestError, match="user id"):
        raw(user_id=" ").validate()
