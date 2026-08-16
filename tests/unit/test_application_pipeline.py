"""Stage-18 pipeline.

The whole chain with a fake provider and an injected retriever, so nothing here
reads a dataset, builds a graph or spends a token.

Two properties carry most of the weight. Generate must not touch the parser, the
extractor or the mapper — it is asked about a requirement no rule satisfies, and
running rule stages over a requirement would either fail or, worse, succeed on
nonsense — so those three are replaced with objects that raise if called. And
the context must be validated before the provider is, so a package the engine
would refuse is never paid for; that is checked by counting provider calls after
a refusal rather than by reading the code.

The response each fake provider returns is built against the package this test
predicts the pipeline will build. If the pipeline built a different one, the
citations would not resolve and Stage-16 would refuse the result, so the
prediction is itself under test.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

import pytest

from src.application.pipeline import Pipeline
from src.application.provider_factory import (
    API_KEY_SECRET,
    provider_from_config,
)
from src.application.requests import EngineRequest
from src.application.retrieval import RetrievalService
from src.application.runtime import RuntimeFactory
from src.config.exceptions import InvalidConfigValueError, MissingSecretError
from src.config.secrets import Secret
from src.config.settings import (
    EngineConfig,
    EngineSettings,
    LoggingSettings,
    PathSettings,
    SecuritySettings,
)
from src.config.types import Environment, LogFormat, LogLevel, LogOutput, SecretsProvider
from src.context.context_builder import ContextBuilder, rule_context_from_parsed
from src.context.exceptions import ContextValidationError
from src.context.validation import ContextIssue, ContextValidationResult
from src.core.exceptions import InvalidReasoningRequestError, ReasoningValidationError
from src.core.models import AnalyzeResult, EnhanceResult, GenerateResult
from src.core.types import ReasoningOperation
from src.entities.exceptions import ExtractionFailureError
from src.entities.extractor import EntityExtractor
from src.formatter.exceptions import OperationMismatchError
from src.formatter.formatter import format_result
from src.graphrag.exceptions import IndexNotBuiltError
from src.graphrag.models import RetrievalQuery, RetrievalResult
from src.llm.exceptions import LLMRateLimitError
from src.llm.gemini_provider import PROVIDER_NAME
from src.mapping.entity_mapper import EntityMapper
from src.parser.exceptions import InvalidRuleFormatError
from src.parser.parser import RuleParser
from src.validation.engine import ValidationEngine
from src.validation.exceptions import EvidenceValidationError, ValidationEngineError
from tests.fixtures import stage15 as fixtures

USER = "8a9ffc32-8495-4a25-a616-362d90f35dcc"
RULE_ID = "1bdc1065-5bd4-4dd6-a6df-c111d643ff90"
REQUIREMENT = "Detect encoded PowerShell command execution on Windows endpoints."
FIXED_ID = "80ea7075-5585-4f0f-914a-f643b4c8c3f2"
ROOT = Path(__file__).resolve().parents[2]

RESPONSES = {
    ReasoningOperation.ANALYZE: fixtures.analyze_response,
    ReasoningOperation.ENHANCE: fixtures.enhance_response,
    ReasoningOperation.GENERATE: fixtures.generate_response,
}
RESULT_TYPES = {
    ReasoningOperation.ANALYZE: AnalyzeResult,
    ReasoningOperation.ENHANCE: EnhanceResult,
    ReasoningOperation.GENERATE: GenerateResult,
}
RULE_OPS = [ReasoningOperation.ANALYZE, ReasoningOperation.ENHANCE]


# --------------------------------------------------------------------------- doubles


class StubRetriever:
    """A retriever answering with one prepared result."""

    def __init__(self, result: RetrievalResult | None = None) -> None:
        self.result = result if result is not None else fixtures.retrieval_result()
        self.queries: list[RetrievalQuery] = []

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        self.queries.append(query)
        return self.result


class FailingRetriever:
    """A retriever that raises what an unbuilt index raises."""

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        raise IndexNotBuiltError("GraphRagRetriever")


class ForbiddenStage:
    """A stand-in for a stage that must not run, whatever it is asked."""

    def __init__(self, name: str) -> None:
        self.name = name

    def _refuse(self, *args, **kwargs):
        raise AssertionError(f"{self.name} must not be called for this operation")

    parse = extract = map = _refuse


class CountingParser:
    """The real parser, counting its calls."""

    def __init__(self) -> None:
        self.inner = RuleParser()
        self.calls = 0

    def parse(self, text: str):
        self.calls += 1
        return self.inner.parse(text)


class RaisingParser:
    """A parser that raises Stage-08's own error."""

    def parse(self, text: str):
        raise InvalidRuleFormatError("the document is neither JSON nor YAML")


class RaisingExtractor:
    """An extractor that raises Stage-09's own error."""

    def extract(self, rule):
        raise ExtractionFailureError("field", "the rule body could not be walked")


class RejectingValidator:
    """A context validator that refuses every package."""

    def validate(self, package) -> ContextValidationResult:
        return ContextValidationResult(
            issues=(ContextIssue("budget", "the package exceeds its character budget"),)
        )


class RecordingValidator:
    """The real Stage-16 engine, keeping what it was asked to accept."""

    def __init__(self) -> None:
        self.inner = ValidationEngine()
        self.seen: list[object] = []

    def validate_or_raise(self, result, package, **kwargs):
        self.seen.append(result)
        return self.inner.validate_or_raise(result, package, **kwargs)


# --------------------------------------------------------------------------- helpers


def prepared(operation: ReasoningOperation):
    """Return the package the pipeline is expected to build for one operation."""
    retrieval = fixtures.retrieval_result()
    if operation is ReasoningOperation.GENERATE:
        return ContextBuilder().build(
            operation.context_operation,
            rule=None,
            entities=None,
            mappings=None,
            retrieval=retrieval,
        )
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    entities = EntityExtractor().extract(parsed)
    return ContextBuilder().build(
        operation.context_operation,
        rule=rule_context_from_parsed(parsed),
        entities=entities,
        mappings=EntityMapper().map(entities),
        retrieval=retrieval,
    )


def request_for(operation: ReasoningOperation, **overrides) -> EngineRequest:
    """Return a valid request for one operation."""
    if operation is ReasoningOperation.GENERATE:
        fields = {"operation": operation, "user_id": USER, "requirement": REQUIREMENT}
    else:
        fields = {
            "operation": operation,
            "user_id": USER,
            "rule_text": fixtures.RULE_TEXT,
            "rule_id": RULE_ID,
        }
    return EngineRequest(**{**fields, **overrides})


def runtime_factory() -> RuntimeFactory:
    """Return a factory with every source of variation pinned."""
    from datetime import UTC, datetime

    return RuntimeFactory(
        now=lambda: datetime(2026, 7, 24, 9, 15, 30, tzinfo=UTC),
        new_id=lambda: FIXED_ID,
        timer=lambda: 0.0,
    )


def pipeline_for(operation: ReasoningOperation, **overrides) -> tuple[Pipeline, object]:
    """Return a pipeline answering one operation, and the provider behind it."""
    provider = fixtures.provider_returning([RESPONSES[operation](prepared(operation))])
    fields = {
        "engine": fixtures.engine_of(provider),
        "retrieval": RetrievalService.of(StubRetriever()),
        "runtime": runtime_factory(),
    }
    if operation is ReasoningOperation.GENERATE:
        forbidden = ForbiddenStage("the rule stages")
        fields |= {"parser": forbidden, "extractor": forbidden, "mapper": forbidden}
    return Pipeline(**{**fields, **overrides}), provider


def engine_config(provider: str = PROVIDER_NAME) -> EngineConfig:
    """Return a configuration naming one provider, with the real prompt tree."""
    return EngineConfig(
        engine=EngineSettings(
            name="odosian-ai-engine",
            environment=Environment.DEVELOPMENT,
            request_timeout_seconds=60,
            max_concurrent_requests=4,
        ),
        paths=PathSettings(
            resources_dir=ROOT / "resources",
            knowledge_dir=ROOT / "resources" / "knowledge",
            prompts_dir=fixtures.PROMPTS_DIR,
        ),
        model=dataclasses.replace(fixtures.model_settings(), provider=provider),
        logging=LoggingSettings(
            level=LogLevel.INFO,
            format=LogFormat.TEXT,
            output=LogOutput.STDOUT,
            file_path=None,
            max_bytes=1024,
            backup_count=1,
        ),
        security=SecuritySettings(
            secrets_provider=SecretsProvider.ENVIRONMENT,
            secrets_file=None,
            required_secrets=(API_KEY_SECRET,),
        ),
    )


# --------------------------------------------------------------------------- dispatch


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_each_operation_produces_its_own_contract_document(operation):
    pipeline, _ = pipeline_for(operation)
    document = pipeline.run(request_for(operation))
    assert document["analysis"]["analysisType"] == operation.value


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_each_document_is_json_serialisable_as_produced(operation):
    pipeline, _ = pipeline_for(operation)
    document = pipeline.run(request_for(operation))
    assert json.loads(json.dumps(document)) == document


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_the_formatter_receives_the_result_type_the_operation_produces(operation):
    """Stage-17 dispatches on type, so the wrong type would raise rather than mislead."""
    recorder = RecordingValidator()
    pipeline, _ = pipeline_for(operation, validator=recorder)
    pipeline.run(request_for(operation))
    assert isinstance(recorder.seen[0], RESULT_TYPES[operation])


def test_a_mismatched_result_type_is_refused_by_the_formatter():
    """What the pipeline hands Stage-17 is the only thing standing between the two."""
    envelope = runtime_factory().create(
        request_for(ReasoningOperation.ANALYZE), started=0.0, input_query=""
    )
    with pytest.raises(OperationMismatchError):
        format_result(object(), envelope)


def test_the_analyze_document_carries_the_derived_grade():
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    analysis = pipeline.run(request_for(ReasoningOperation.ANALYZE))["analysis"]
    assert (analysis["score"], analysis["rating"], analysis["fpRisk"]) == (62, "C", "medium")


def test_the_enhance_document_carries_the_sentinels_and_a_changelog():
    pipeline, _ = pipeline_for(ReasoningOperation.ENHANCE)
    analysis = pipeline.run(request_for(ReasoningOperation.ENHANCE))["analysis"]
    assert (analysis["score"], analysis["rating"]) == (0, "")
    assert analysis["changelog"][0]["change"].startswith(("Added ", "Removed ", "Changed "))


def test_the_generate_document_carries_the_rule_and_its_schedule():
    pipeline, _ = pipeline_for(ReasoningOperation.GENERATE)
    analysis = pipeline.run(request_for(ReasoningOperation.GENERATE))["analysis"]
    assert analysis["language"] == "kuery"
    assert (analysis["interval"], analysis["fromTime"], analysis["maxSignals"]) == (
        "5m",
        "now-6m",
        100,
    )


def test_generate_never_calls_the_parser_the_extractor_or_the_mapper():
    """Forbidden stands in for all three and raises if any of them is reached."""
    pipeline, _ = pipeline_for(ReasoningOperation.GENERATE)
    assert isinstance(pipeline.parser, ForbiddenStage)
    pipeline.run(request_for(ReasoningOperation.GENERATE))


@pytest.mark.parametrize("operation", RULE_OPS, ids=lambda o: o.value)
def test_a_rule_operation_does_call_the_parser(operation):
    counting = CountingParser()
    pipeline, _ = pipeline_for(operation, parser=counting)
    pipeline.run(request_for(operation))
    assert counting.calls == 1


def test_generate_seeds_retrieval_with_the_requirement_alone():
    retriever = StubRetriever()
    pipeline, _ = pipeline_for(
        ReasoningOperation.GENERATE, retrieval=RetrievalService.of(retriever)
    )
    pipeline.run(request_for(ReasoningOperation.GENERATE))
    query = retriever.queries[0]
    assert query.text == REQUIREMENT
    assert (query.entity_ids, query.canonical_fields) == ((), ())


@pytest.mark.parametrize("operation", RULE_OPS, ids=lambda o: o.value)
def test_a_rule_operation_seeds_retrieval_with_its_identifiers(operation):
    retriever = StubRetriever()
    pipeline, _ = pipeline_for(operation, retrieval=RetrievalService.of(retriever))
    pipeline.run(request_for(operation))
    assert retriever.queries[0].entity_ids


# --------------------------------------------------------------------------- runtime


def test_the_document_carries_the_injected_runtime_values():
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    analysis = pipeline.run(request_for(ReasoningOperation.ANALYZE))["analysis"]
    assert analysis["id"] == FIXED_ID
    assert analysis["createdAt"] == "2026-07-24T09:15:30.000Z"
    assert analysis["latencyMs"] == 0
    assert analysis["userId"] == USER
    assert analysis["ruleId"] == RULE_ID


def test_the_analyze_document_reports_the_rule_query_as_its_input():
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    analysis = pipeline.run(request_for(ReasoningOperation.ANALYZE))["analysis"]
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    assert analysis["inputQuery"] == rule_context_from_parsed(parsed).query


def test_an_ad_hoc_analysis_reports_a_null_rule_id():
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    analysis = pipeline.run(request_for(ReasoningOperation.ANALYZE, rule_id=None))["analysis"]
    assert analysis["ruleId"] is None


def test_the_model_and_tokens_come_from_the_result_not_the_runtime():
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    analysis = pipeline.run(request_for(ReasoningOperation.ANALYZE))["analysis"]
    assert analysis["modelUsed"] == "fake-model"
    assert analysis["tokensUsed"] > 0


# --------------------------------------------------------------------------- gating


def test_an_invalid_request_is_refused_before_anything_runs():
    pipeline, provider = pipeline_for(ReasoningOperation.ANALYZE)
    with pytest.raises(InvalidReasoningRequestError):
        pipeline.run(request_for(ReasoningOperation.ANALYZE, user_id="  "))
    assert provider.calls == 0


def test_a_refused_context_never_reaches_the_provider():
    pipeline, provider = pipeline_for(
        ReasoningOperation.ANALYZE, context_validator=RejectingValidator()
    )
    with pytest.raises(ContextValidationError):
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert provider.calls == 0


def test_a_valid_context_does_reach_the_provider():
    pipeline, provider = pipeline_for(ReasoningOperation.ANALYZE)
    pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert provider.calls == 1


# --------------------------------------------------------------------------- errors


def test_a_parser_failure_arrives_as_a_parser_failure():
    pipeline, provider = pipeline_for(ReasoningOperation.ANALYZE, parser=RaisingParser())
    with pytest.raises(InvalidRuleFormatError):
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert provider.calls == 0


def test_an_extraction_failure_arrives_as_an_extraction_failure():
    pipeline, provider = pipeline_for(ReasoningOperation.ANALYZE, extractor=RaisingExtractor())
    with pytest.raises(ExtractionFailureError):
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert provider.calls == 0


def test_a_retrieval_failure_arrives_as_a_retrieval_failure():
    pipeline, provider = pipeline_for(
        ReasoningOperation.ANALYZE, retrieval=RetrievalService.of(FailingRetriever())
    )
    with pytest.raises(IndexNotBuiltError):
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert provider.calls == 0


def test_a_provider_failure_keeps_its_own_type_and_is_not_retried_again():
    provider = fixtures.FakeProvider(
        failures=[LLMRateLimitError("slow down", provider="fake")] * 8
    )
    pipeline = Pipeline(
        engine=fixtures.engine_of(provider),
        retrieval=RetrievalService.of(StubRetriever()),
        runtime=runtime_factory(),
    )
    with pytest.raises(LLMRateLimitError):
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert provider.calls == fixtures.model_settings().max_retries + 1


def _dangling(node):
    """Return the body with every citation pointing at an item that does not exist."""
    if isinstance(node, dict):
        return {
            key: ("knowledge:9999" if key == "item_id" else _dangling(value))
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_dangling(item) for item in node]
    return node


def test_a_fabricated_citation_arrives_as_stage_fifteen_refusal():
    """Stage-15 validates inside the engine, so it refuses this before Stage-16 sees it."""
    body = _dangling(fixtures.analyze_response(prepared(ReasoningOperation.ANALYZE)))
    provider = fixtures.provider_returning([body])
    pipeline = Pipeline(
        engine=fixtures.engine_of(provider),
        retrieval=RetrievalService.of(StubRetriever()),
        runtime=runtime_factory(),
    )
    with pytest.raises(ReasoningValidationError, match="fabricated_reference"):
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert provider.calls == 1


def test_a_stage_sixteen_refusal_reaches_the_caller_unwrapped():
    """The refusal is an answer. It must not be rebranded on its way out."""

    class RefusingValidator:
        def validate_or_raise(self, result, package, **kwargs):
            report = ValidationEngine().validate(result, package)
            raise EvidenceValidationError(report)

    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE, validator=RefusingValidator())
    with pytest.raises(EvidenceValidationError) as caught:
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert isinstance(caught.value, ValidationEngineError)


def test_no_stage_eighteen_exception_type_was_introduced():
    import src.application as application

    assert not [name for name in application.__all__ if name.endswith("Error")]


# --------------------------------------------------------------------------- provider


def test_the_factory_builds_the_provider_the_configuration_names(monkeypatch):
    built: dict[str, object] = {}

    class StubGemini:
        def __init__(self, api_key):
            built["key"] = api_key

    monkeypatch.setattr("src.application.provider_factory.GeminiProvider", StubGemini)
    secret = Secret(API_KEY_SECRET, "not-a-real-key")
    provider = provider_from_config(engine_config(), {API_KEY_SECRET: secret})
    assert isinstance(provider, StubGemini)
    assert built["key"] is secret


def test_the_factory_refuses_a_provider_the_engine_does_not_implement():
    with pytest.raises(InvalidConfigValueError, match="model.provider"):
        provider_from_config(engine_config("openai"), {API_KEY_SECRET: Secret("k", "v")})


def test_the_factory_refuses_to_run_without_the_declared_secret():
    with pytest.raises(MissingSecretError, match=API_KEY_SECRET):
        provider_from_config(engine_config(), {})


def test_the_factory_never_reveals_the_credential_in_its_refusals():
    try:
        provider_from_config(engine_config("openai"), {API_KEY_SECRET: Secret("k", "s3cret")})
    except InvalidConfigValueError as error:
        assert "s3cret" not in str(error)


def test_the_pipeline_accepts_an_injected_provider_and_builds_no_other():
    """Nothing in the pipeline module names a concrete provider."""
    import src.application.pipeline as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "GeminiProvider" not in source
    assert "gemini" not in source.lower()


def test_create_wires_a_provider_without_touching_the_corpus():
    provider = fixtures.provider_returning([RESPONSES[ReasoningOperation.ANALYZE](
        prepared(ReasoningOperation.ANALYZE)
    )])
    pipeline = Pipeline.create(
        engine_config(),
        provider,
        retrieval=RetrievalService.of(StubRetriever()),
        runtime=runtime_factory(),
    )
    document = pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert document["analysis"]["id"] == FIXED_ID


# --------------------------------------------------------------------------- logging


def test_the_log_line_states_the_shape_and_never_the_content(caplog):
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    with caplog.at_level(logging.INFO):
        pipeline.run(request_for(ReasoningOperation.ANALYZE))
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "pipeline completed operation=analyze" in logged
    assert USER not in logged
    assert "powershell" not in logged.lower()
    assert fixtures.RULE_TEXT not in logged
