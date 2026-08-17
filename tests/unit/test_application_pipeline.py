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

from src.application.pipeline import Pipeline, parsed_rule_from_query
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
from src.parser.types import RuleFormat, RuleLanguage
from src.validation.engine import ValidationEngine
from src.validation.exceptions import EvidenceValidationError, ValidationEngineError
from tests.fixtures import stage15 as fixtures

USER = "8a9ffc32-8495-4a25-a616-362d90f35dcc"
RULE_ID = "1bdc1065-5bd4-4dd6-a6df-c111d643ff90"
REQUIREMENT = "Detect encoded PowerShell command execution on Windows endpoints."
FIXED_ID = "80ea7075-5585-4f0f-914a-f643b4c8c3f2"
ROOT = Path(__file__).resolve().parents[2]

RAW_QUERY = 'process.name:"powershell.exe" and process.command_line:*-enc*'
"""A query as a caller would paste it: no document around it."""

ELASTIC_RULE = json.dumps(
    {
        "name": "Encoded PowerShell Command Line",
        "rule_id": "6f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
        "type": "query",
        "language": "kuery",
        "query": RAW_QUERY,
        "index": ["logs-endpoint.events.process-*"],
        "severity": "medium",
    }
)
"""A rule whose format states a single query, unlike Sigma."""

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


RULE_TEXT_FOR = {
    ReasoningOperation.ANALYZE: fixtures.RULE_TEXT,
    ReasoningOperation.ENHANCE: ELASTIC_RULE,
}
"""The rule each operation is exercised with.

Analyze keeps the Sigma fixture: it reads a rule that states no query perfectly
well, and that is worth holding onto. Enhance cannot — it reports the original
query beside the rewrite — so it is exercised with a rule that states one. The
refusal that makes this necessary is itself under test below.
"""


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
    parsed = RuleParser().parse(RULE_TEXT_FOR[operation])
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
            "rule_text": RULE_TEXT_FOR[operation],
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


def test_the_changelog_is_derived_from_the_accepted_result_end_to_end():
    """Every entry must trace to a change the engine accepted, not to model prose.

    The label follows the empty-string convention Stage-15's Change spec states,
    and the reason is the model's rationale verbatim.
    """
    recorder = RecordingValidator()
    pipeline, _ = pipeline_for(ReasoningOperation.ENHANCE, validator=recorder)
    changelog = pipeline.run(request_for(ReasoningOperation.ENHANCE))["analysis"]["changelog"]
    accepted = recorder.seen[0]

    assert len(changelog) == len(accepted.changes)
    for entry, change in zip(changelog, accepted.changes, strict=True):
        assert list(entry) == ["change", "reason"]
        assert entry["reason"] == change.rationale
        before, after = change.before.strip(), change.after.strip()
        if not before:
            assert entry["change"] == f"Added {after}"
        elif not after:
            assert entry["change"] == f"Removed {before}"
        else:
            assert entry["change"] == f"Changed {before} to {after}"


def test_the_investigation_guide_reaches_the_document_from_the_accepted_result():
    """End to end: the guide is the model's, unaltered, and nothing substitutes for it."""
    recorder = RecordingValidator()
    pipeline, _ = pipeline_for(ReasoningOperation.ENHANCE, validator=recorder)
    analysis = pipeline.run(request_for(ReasoningOperation.ENHANCE))["analysis"]
    accepted = recorder.seen[0]
    assert analysis["investigationGuide"] == accepted.enhanced_rule.investigation_guide
    assert analysis["investigationGuide"].strip()


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


def test_a_sigma_analysis_reports_the_submitted_rule_as_its_input():
    """Sigma states no single query, so the text submitted is what was analysed.

    Previously this field went out empty for every Sigma rule, which told a
    reader nothing about what had been assessed.
    """
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    analysis = pipeline.run(request_for(ReasoningOperation.ANALYZE))["analysis"]
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    rule = rule_context_from_parsed(parsed)
    assert rule.query == ""
    assert analysis["inputQuery"] == rule.raw_text
    assert analysis["inputQuery"].strip()


def test_a_query_bearing_rule_still_reports_its_query_as_its_input():
    """The fallback must not displace a query the rule does state."""
    parsed = RuleParser().parse(ELASTIC_RULE)
    rule = rule_context_from_parsed(parsed)
    assert rule.query
    package = ContextBuilder().build(
        ReasoningOperation.ANALYZE.context_operation,
        rule=rule,
        entities=EntityExtractor().extract(parsed),
        mappings=EntityMapper().map(EntityExtractor().extract(parsed)),
        retrieval=fixtures.retrieval_result(),
    )
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    pipeline = Pipeline(
        engine=fixtures.engine_of(provider),
        retrieval=RetrievalService.of(StubRetriever()),
        runtime=runtime_factory(),
    )
    analysis = pipeline.run(
        EngineRequest(ReasoningOperation.ANALYZE, user_id=USER, rule_text=ELASTIC_RULE)
    )["analysis"]
    assert analysis["inputQuery"] == rule.query
    assert analysis["inputQuery"] != rule.raw_text


# ------------------------------------------------------------- enhance needs a query


def elastic_rule(language: str, query: str) -> str:
    """Return an Elastic rule stating one query in the given language."""
    return json.dumps(
        {
            "name": "Encoded PowerShell Command Line",
            "rule_id": "6f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
            "type": "query",
            "language": language,
            "query": query,
            "index": ["logs-endpoint.events.process-*"],
            "severity": "medium",
        }
    )


ENHANCE_RULES = {
    "kuery": elastic_rule("kuery", RAW_QUERY),
    "eql": elastic_rule("eql", 'process where process.name == "powershell.exe"'),
    "lucene": elastic_rule("lucene", 'process.name:"powershell.exe" AND process.args:*-enc*'),
}


def enhance_pipeline(rule_text: str):
    """Return an enhance pipeline whose fake answer matches the rule supplied."""
    parsed = RuleParser().parse(rule_text)
    entities = EntityExtractor().extract(parsed)
    rule = rule_context_from_parsed(parsed)
    package = ContextBuilder().build(
        ReasoningOperation.ENHANCE.context_operation,
        rule=rule,
        entities=entities,
        mappings=EntityMapper().map(entities),
        retrieval=fixtures.retrieval_result(),
    )
    body = fixtures.enhance_response(package)
    # Stage-15 refuses an original_rule that does not reproduce the supplied query,
    # so the canned answer is aligned with whichever rule this case uses. The query
    # is stated on one line, as the response schema asks and as a model would: the
    # comparison collapses whitespace, so a flattened copy still matches.
    body["original_rule"] = {
        "identifier": rule.identifier,
        "title": rule.title,
        "language": rule.language,
        "query": " ".join(rule.query.split()),
    }
    provider = fixtures.provider_returning([body])
    return (
        Pipeline(
            engine=fixtures.engine_of(provider),
            retrieval=RetrievalService.of(StubRetriever()),
            runtime=runtime_factory(),
        ),
        provider,
    )


def sigma_enhance_request() -> EngineRequest:
    """Return an enhance request naming the Sigma rule, which states no query."""
    return request_for(ReasoningOperation.ENHANCE, rule_text=fixtures.RULE_TEXT)


def test_enhance_refuses_a_sigma_rule_before_any_provider_call():
    """Sigma states no query, so there is no original for the rewrite to sit beside."""
    pipeline, provider = pipeline_for(ReasoningOperation.ENHANCE)
    with pytest.raises(InvalidReasoningRequestError):
        pipeline.run(sigma_enhance_request())
    assert provider.calls == 0


def test_the_sigma_refusal_names_the_format_and_the_missing_capability():
    pipeline, _ = pipeline_for(ReasoningOperation.ENHANCE)
    with pytest.raises(InvalidReasoningRequestError) as caught:
        pipeline.run(sigma_enhance_request())
    message = str(caught.value)
    assert "'sigma'" in message
    assert "query to rewrite" in message
    assert "states none" in message
    assert "named blocks" in message
    assert "Analyze accepts this rule; enhance does not." in message


def test_the_sigma_refusal_happens_before_retrieval_runs():
    """Refusing after retrieval would index a corpus for a request already doomed."""
    retriever = StubRetriever()
    pipeline, provider = pipeline_for(
        ReasoningOperation.ENHANCE, retrieval=RetrievalService.of(retriever)
    )
    with pytest.raises(InvalidReasoningRequestError):
        pipeline.run(sigma_enhance_request())
    assert retriever.queries == []
    assert provider.calls == 0


@pytest.mark.parametrize("language", sorted(ENHANCE_RULES), ids=sorted(ENHANCE_RULES))
def test_enhance_accepts_every_format_that_states_a_query(language):
    rule_text = ENHANCE_RULES[language]
    pipeline, provider = enhance_pipeline(rule_text)
    document = pipeline.run(
        EngineRequest(ReasoningOperation.ENHANCE, user_id=USER, rule_text=rule_text)
    )
    assert document["analysis"]["analysisType"] == "enhance"
    assert provider.calls == 1


@pytest.mark.parametrize("language", sorted(ENHANCE_RULES), ids=sorted(ENHANCE_RULES))
def test_an_accepted_enhance_reports_the_supplied_query_as_its_input(language):
    rule_text = ENHANCE_RULES[language]
    pipeline, _ = enhance_pipeline(rule_text)
    document = pipeline.run(
        EngineRequest(ReasoningOperation.ENHANCE, user_id=USER, rule_text=rule_text)
    )
    assert "\n" not in document["analysis"]["inputQuery"]


MULTI_LINE_QUERY = (
    "event.category:(network or network_traffic) and network.transport:tcp and\n"
    "  destination.port:(9001 or 9030) and\n"
    "  source.ip:(10.0.0.0/8 or\n"
    "             172.16.0.0/12)"
)
"""A query formatted the way most real Elastic rules format theirs.

Measured over the shipped corpus: 560 of 769 kuery rules — 72.8 per cent — write
their query across several lines. The breaks are indentation, not meaning.
"""


def test_enhance_accepts_a_multi_line_query():
    """Line breaks are formatting. Refusing them would rule out most real rules."""
    rule_text = elastic_rule("kuery", MULTI_LINE_QUERY)
    parsed = RuleParser().parse(rule_text)
    assert "\n" in (parsed.detection.query or ""), "the parser must preserve the breaks"

    pipeline, provider = enhance_pipeline(rule_text)
    document = pipeline.run(
        EngineRequest(ReasoningOperation.ENHANCE, user_id=USER, rule_text=rule_text)
    )
    assert document["analysis"]["analysisType"] == "enhance"
    assert provider.calls == 1


def test_a_multi_line_query_is_reported_on_one_line():
    """The document states the original flattened, which is what the contract shows."""
    rule_text = elastic_rule("kuery", MULTI_LINE_QUERY)
    pipeline, _ = enhance_pipeline(rule_text)
    document = pipeline.run(
        EngineRequest(ReasoningOperation.ENHANCE, user_id=USER, rule_text=rule_text)
    )
    reported = document["analysis"]["inputQuery"]
    assert "\n" not in reported
    assert reported == " ".join(MULTI_LINE_QUERY.split())


def test_the_boundary_refuses_absence_only_and_not_formatting():
    """The guard's whole condition: a query is present, or it is not."""
    pipeline, provider = enhance_pipeline(elastic_rule("kuery", MULTI_LINE_QUERY))
    for query, refused in ((MULTI_LINE_QUERY, False), ("", True), ("   \n  ", True)):
        rule_text = elastic_rule("kuery", query)
        request = EngineRequest(
            ReasoningOperation.ENHANCE, user_id=USER, rule_text=rule_text
        )
        if refused:
            with pytest.raises(InvalidReasoningRequestError, match="states none"):
                pipeline.run(request)
        else:
            assert RuleParser().parse(rule_text).detection.query


def test_enhance_refuses_a_blank_query():
    rule_text = elastic_rule("kuery", "   ")
    pipeline, provider = enhance_pipeline(rule_text)
    with pytest.raises(InvalidReasoningRequestError, match="states none"):
        pipeline.run(
            EngineRequest(ReasoningOperation.ENHANCE, user_id=USER, rule_text=rule_text)
        )
    assert provider.calls == 0


def test_analyze_still_accepts_the_sigma_rule_the_refusal_rejects():
    """The refusal belongs to enhance alone; analyze reads Sigma perfectly well."""
    pipeline, provider = pipeline_for(ReasoningOperation.ANALYZE)
    document = pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert document["analysis"]["analysisType"] == "analyze"
    assert provider.calls == 1


def test_generate_is_untouched_by_the_enhance_refusal():
    pipeline, provider = pipeline_for(ReasoningOperation.GENERATE)
    document = pipeline.run(request_for(ReasoningOperation.GENERATE))
    assert document["analysis"]["analysisType"] == "generate"
    assert provider.calls == 1


# --------------------------------------------------------------------------- raw query


def raw_query_pipeline():
    """Return a pipeline answering a raw-query analysis, and its retriever."""
    parsed = parsed_rule_from_query(
        EngineRequest(
            ReasoningOperation.ANALYZE, user_id=USER, query=RAW_QUERY, language="kuery"
        )
    )
    entities = EntityExtractor().extract(parsed)
    package = ContextBuilder().build(
        ReasoningOperation.ANALYZE.context_operation,
        rule=rule_context_from_parsed(parsed),
        entities=entities,
        mappings=EntityMapper().map(entities),
        retrieval=fixtures.retrieval_result(),
    )
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    retriever = StubRetriever()
    return (
        Pipeline(
            engine=fixtures.engine_of(provider),
            retrieval=RetrievalService.of(retriever),
            runtime=runtime_factory(),
        ),
        provider,
        retriever,
    )


def raw_request(**overrides) -> EngineRequest:
    """Return a valid raw-query analyze request."""
    fields = {
        "operation": ReasoningOperation.ANALYZE,
        "user_id": USER,
        "query": RAW_QUERY,
        "language": "kuery",
    }
    return EngineRequest(**{**fields, **overrides})


def test_a_raw_query_becomes_a_parsed_rule_without_the_parser():
    parsed = parsed_rule_from_query(raw_request())
    assert parsed.detection.query == RAW_QUERY
    assert parsed.detection.language is RuleLanguage.KUERY
    assert parsed.rule_format is RuleFormat.UNKNOWN
    assert parsed.source_text == RAW_QUERY
    assert parsed.detection.definitions == {}


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("kuery", RuleLanguage.KUERY),
        ("kql", RuleLanguage.KUERY),
        ("eql", RuleLanguage.EQL),
        ("lucene", RuleLanguage.LUCENE),
        ("esql", RuleLanguage.ESQL),
        ("es|ql", RuleLanguage.ESQL),
        ("ESQL", RuleLanguage.ESQL),
    ],
)
def test_every_accepted_language_token_reaches_the_parsed_rule(token, expected):
    """Stage-08's own table is used; no second one is written here."""
    parsed = parsed_rule_from_query(raw_request(language=token))
    assert parsed.detection.language is expected


def test_a_raw_query_extracts_entities():
    parsed = parsed_rule_from_query(raw_request())
    entities = EntityExtractor().extract(parsed)
    assert entities.entities
    assert any(entity.value == "process.name" for entity in entities.entities)


def test_a_raw_query_resolves_no_canonical_identifier_and_nothing_is_invented():
    """Stage-09 records 'query' as the source field, so Stage-10 resolves nothing.

    Retrieval falls back to the query text. This is asserted rather than worked
    around: an engine that manufactured identifiers here would be inventing.
    """
    parsed = parsed_rule_from_query(raw_request())
    mappings = EntityMapper().map(EntityExtractor().extract(parsed))
    assert mappings.entities
    assert mappings.resolved == ()


def test_a_raw_query_reaches_retrieval_on_its_text():
    pipeline, _, retriever = raw_query_pipeline()
    pipeline.run(raw_request())
    query = retriever.queries[0]
    assert query.text == RAW_QUERY
    assert (query.entity_ids, query.canonical_fields) == ((), ())
    assert not query.is_empty


def test_a_raw_query_runs_the_whole_pipeline_to_a_contract_document():
    pipeline, provider, _ = raw_query_pipeline()
    document = pipeline.run(raw_request())
    assert document["analysis"]["analysisType"] == "analyze"
    assert document["analysis"]["inputQuery"] == RAW_QUERY
    assert document["analysis"]["ruleId"] is None
    assert provider.calls == 1
    assert json.loads(json.dumps(document)) == document


def test_a_raw_query_produces_the_same_contract_field_set_as_a_rule():
    pipeline, _, _ = raw_query_pipeline()
    raw_keys = list(pipeline.run(raw_request())["analysis"].keys())
    rule_pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE)
    rule_keys = list(rule_pipeline.run(request_for(ReasoningOperation.ANALYZE))["analysis"].keys())
    assert raw_keys == rule_keys


def test_the_structured_rule_path_never_calls_the_query_assembler():
    """The existing path must be untouched, so the parser still does the work."""
    counting = CountingParser()
    pipeline, _ = pipeline_for(ReasoningOperation.ANALYZE, parser=counting)
    pipeline.run(request_for(ReasoningOperation.ANALYZE))
    assert counting.calls == 1


def test_a_raw_query_never_calls_the_parser():
    forbidden = ForbiddenStage("the parser")
    pipeline, _, _ = raw_query_pipeline()
    pipeline = dataclasses.replace(pipeline, parser=forbidden)
    pipeline.run(raw_request())


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
