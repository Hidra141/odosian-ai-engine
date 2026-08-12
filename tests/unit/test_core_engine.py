"""Stage-15 engine.

Orchestration, failure handling and the boundary with Stage-06 and Stage-07.
"""

from __future__ import annotations

import logging

import pytest

from src.context.models import ContextPackage, RuleContext
from src.context.types import ContextOperation
from src.core.exceptions import (
    InvalidReasoningRequestError,
    PromptRenderingError,
    ResponseSchemaError,
)
from src.core.models import AnalyzeRequest, EnhanceRequest, GenerateRequest, ReasoningRequest
from src.core.types import ReasoningOperation
from src.llm.exceptions import (
    LLMAuthenticationError,
    LLMInvalidJSONError,
    LLMInvalidResponseError,
    LLMRateLimitError,
    LLMServiceUnavailableError,
)
from src.prompts.prompt_repository import PromptRepository
from tests.fixtures import stage15 as fixtures


def analyze(payloads, package=None):
    package = package if package is not None else fixtures.context_package()
    provider = fixtures.provider_returning(payloads)
    engine = fixtures.engine_of(provider)
    return engine, provider, engine.analyze(AnalyzeRequest(package=package))


def test_analyze_happy_path_returns_a_typed_result():
    package = fixtures.context_package()
    _, provider, result = analyze([fixtures.analyze_response(package)], package)
    assert result.operation is ReasoningOperation.ANALYZE
    assert result.findings[0].finding_id == "F1"
    assert result.recommendations[0].addresses == ("F1",)
    assert result.provenance.provider == "fake"
    assert provider.calls == 1


def test_enhance_happy_path_returns_the_enhanced_rule():
    package = fixtures.context_package(ContextOperation.ENHANCE)
    provider = fixtures.provider_returning([fixtures.enhance_response(package)])
    result = fixtures.engine_of(provider).enhance(EnhanceRequest(package=package))
    assert result.enhanced_rule.risk_score == 47
    assert result.changes[0].change_id == "C1"
    assert result.original_rule.query == fixtures.RULE_QUERY


def test_generate_happy_path_returns_the_generated_rule():
    package = fixtures.context_package(ContextOperation.GENERATE)
    provider = fixtures.provider_returning([fixtures.generate_response(package)])
    result = fixtures.engine_of(provider).generate(GenerateRequest(package=package))
    assert result.generated_rule.rule_type.value == "query"
    assert result.rationale[0].aspect.value == "target_behaviour"
    assert result.mappings[0].technique_id == "T1059.001"


def test_the_prompt_carries_every_variable_and_the_operation_schema():
    package = fixtures.context_package()
    engine, provider, _ = analyze([fixtures.analyze_response(package)], package)
    request = provider.last_request
    assert request.operation == "analyze"
    assert "AnalyzeResponse" in request.instruction or "AnalyzeResponse" in request.system
    assert "{{" not in request.instruction
    assert "{{" not in request.system


@pytest.mark.parametrize(
    "body",
    [
        '```json\n{"operation": "analyze"}\n```',
        '{"operation": "analyze",}',
        '{"operation": "analyze"',
        'Here is the answer: {"operation": "analyze"}',
    ],
    ids=["fenced", "trailing_comma", "truncated", "prose"],
)
def test_malformed_json_is_rejected_and_never_repaired(body):
    package = fixtures.context_package()
    provider = fixtures.provider_returning([body])
    with pytest.raises(LLMInvalidJSONError):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))


def test_an_empty_body_is_rejected():
    package = fixtures.context_package()
    provider = fixtures.provider_returning(["   "])
    with pytest.raises(LLMInvalidResponseError):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))


def test_a_json_array_is_not_a_response():
    package = fixtures.context_package()
    provider = fixtures.provider_returning(["[1, 2, 3]"])
    with pytest.raises(LLMInvalidResponseError):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))


def test_a_response_for_another_schema_is_rejected():
    package = fixtures.context_package()
    provider = fixtures.provider_returning([{"result": "ok", "score": 1}])
    with pytest.raises(ResponseSchemaError) as error:
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    assert error.value.operation == "analyze"
    assert any("missing" in issue for issue in error.value.issues)
    assert any("not defined by the schema" in issue for issue in error.value.issues)


def test_missing_required_fields_are_all_reported():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    del payload["summary"]
    del payload["confidence"]
    provider = fixtures.provider_returning([payload])
    with pytest.raises(ResponseSchemaError) as error:
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    assert len(error.value.issues) == 2


def test_an_invalid_enum_value_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["findings"][0]["severity"] = "catastrophic"
    provider = fixtures.provider_returning([payload])
    with pytest.raises(ResponseSchemaError) as error:
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    assert "$.findings[0].severity" in error.value.issues[0]


def test_a_confidence_outside_its_range_is_rejected():
    package = fixtures.context_package()
    payload = fixtures.analyze_response(package)
    payload["confidence"] = 1.4
    provider = fixtures.provider_returning([payload])
    with pytest.raises(ResponseSchemaError):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))


def test_a_transient_failure_is_retried_under_the_stage_07_policy():
    package = fixtures.context_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    provider.failures = [
        LLMRateLimitError("rate limited", provider="fake", status_code=429),
        LLMServiceUnavailableError("upstream", provider="fake", status_code=503),
        None,
    ]
    result = fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    assert provider.calls == 3
    assert result.operation is ReasoningOperation.ANALYZE


def test_an_authentication_failure_is_not_retried():
    package = fixtures.context_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    provider.failures = [LLMAuthenticationError("rejected", provider="fake", status_code=401)]
    with pytest.raises(LLMAuthenticationError):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    assert provider.calls == 1


def test_retries_stop_at_the_configured_attempt_budget():
    package = fixtures.context_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    provider.failures = [
        LLMRateLimitError("rate limited", provider="fake", status_code=429) for _ in range(5)
    ]
    with pytest.raises(LLMRateLimitError):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    assert provider.calls == fixtures.model_settings().max_retries + 1


def test_a_request_whose_operation_disagrees_with_its_package_is_refused():
    package = fixtures.context_package(ContextOperation.ANALYZE)
    provider = fixtures.provider_returning([])
    with pytest.raises(InvalidReasoningRequestError):
        fixtures.engine_of(provider).enhance(EnhanceRequest(package=package))
    assert provider.calls == 0


def test_a_request_without_a_rule_is_refused():
    package = ContextPackage(operation=ContextOperation.ANALYZE)
    provider = fixtures.provider_returning([])
    with pytest.raises(InvalidReasoningRequestError):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    assert provider.calls == 0


def test_a_generate_request_carries_its_requirement():
    package = fixtures.context_package(
        ContextOperation.GENERATE, rule=RuleContext(raw_text="")
    )
    provider = fixtures.provider_returning([fixtures.generate_response(package)])
    engine = fixtures.engine_of(provider)
    request = GenerateRequest(
        package=package, requirement="Detect encoded PowerShell command execution."
    )
    result = engine.generate(request)
    assert result.generated_rule.title
    assert "Detect encoded PowerShell command execution." in provider.last_request.instruction


def test_a_missing_template_fails_as_a_prompt_rendering_error():
    package = fixtures.context_package()
    provider = fixtures.provider_returning([])
    engine = fixtures.engine_of(provider)
    broken = engine.__class__(
        client=engine.client,
        builder=type(engine.builder)(repository=PromptRepository(root=fixtures.PROMPTS_DIR / "x")),
    )
    with pytest.raises(PromptRenderingError) as error:
        broken.run(ReasoningRequest(ReasoningOperation.ANALYZE, package))
    assert error.value.operation == "analyze"
    assert error.value.__cause__ is not None


def test_no_prompt_or_response_text_is_logged(caplog):
    package = fixtures.context_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    with caplog.at_level(logging.DEBUG):
        fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "powershell.exe" not in logged
    assert "T1059.001" not in logged
    assert "reasoning completed operation=analyze" in logged


def test_a_credential_in_the_rule_never_reaches_the_provider():
    secret = "AIzaSyA1234567890123456789012345678901234"
    package = fixtures.context_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    engine = fixtures.engine_of(provider)
    engine.run(
        ReasoningRequest(
            ReasoningOperation.ANALYZE,
            package,
            RuleContext(raw_text=f"title: leak\napi_key: {secret}\n"),
        )
    )
    request = provider.last_request
    assert secret not in request.instruction
    assert secret not in request.system
    assert secret not in repr(request)


def test_prompt_text_stays_out_of_the_request_repr():
    package = fixtures.context_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))
    rendered = repr(provider.last_request)
    assert "powershell" not in rendered.lower()
    assert "fake-model" in rendered
