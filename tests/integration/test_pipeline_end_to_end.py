"""Stage-18 over the real corpus.

The first test in the project to run the retrieval leg for real: the actual
JSONL datasets, the actual Stage-12 graph built over them, the actual Stage-13
indexes, and an actual query seeded from an actual rule. Every other test in the
suite supplies retrieval as a fixture, so nothing until now proved that the
four stages assemble at all.

The provider is fake. Nothing here calls a model, and the response is built
against the package this module predicts the pipeline will build — so a
prediction that drifted would fail through Stage-16's citation checks rather
than pass quietly.

Building the indexes reads every dataset, so it happens once for the module. A
corpus that is not present is skipped rather than failed: the datasets are
inputs to the repository, not artefacts of it, and a checkout without them is a
legitimate state that no configuration change should be needed to handle.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.application.pipeline import Pipeline
from src.application.requests import EngineRequest
from src.application.retrieval import DEFAULT_SETTINGS, RetrievalService
from src.application.runtime import RuntimeFactory
from src.context.context_builder import ContextBuilder, rule_context_from_parsed
from src.context.validation import ContextValidator
from src.core.types import ReasoningOperation
from src.entities.extractor import EntityExtractor
from src.knowledge.loader.layout import CorpusLayout
from src.knowledge.models.types import KnowledgeSource
from src.mapping.entity_mapper import EntityMapper
from src.parser.parser import RuleParser
from tests.fixtures import stage15 as fixtures

ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_DIR = ROOT / "resources" / "knowledge"
USER = "8a9ffc32-8495-4a25-a616-362d90f35dcc"
RULE_ID = "1bdc1065-5bd4-4dd6-a6df-c111d643ff90"
FIXED_ID = "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e"

RULE_TEXT = """title: Suspicious PowerShell Encoded Command
id: 8a1f2c34-0000-4c11-9f00-2b7a5c9e1234
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.name: powershell.exe
    process.command_line|contains: '-enc'
  condition: selection
falsepositives:
  - Administrative scripts
tags:
  - attack.execution
  - attack.t1059.001
level: medium
"""
"""A rule that states the technique it detects.

The Stage-15 fixture rule does not, which is exactly why it cannot be used here.
Nothing extracts a technique it was never given, so nothing seeds retrieval with
one, and the corpus returns no ATT&CK record — correct behaviour that leaves the
package with no MITRE material for a response to cite. A rule that names its
technique is what makes the identifier route observable at all.
"""

REQUIREMENT = (
    "Detect encoded PowerShell command execution on Windows endpoints, "
    "covering ATT&CK technique T1059.001."
)
"""A requirement naming its technique.

Generate seeds retrieval with text alone — there is nothing parsed to resolve —
so the identifier has to be in the words the caller wrote or the corpus has no
reason to return the technique.
"""

RESPONSES = {
    ReasoningOperation.ANALYZE: fixtures.analyze_response,
    ReasoningOperation.ENHANCE: fixtures.enhance_response,
    ReasoningOperation.GENERATE: fixtures.generate_response,
}


@pytest.fixture(scope="module")
def retrieval() -> RetrievalService:
    """Assemble the corpus, the graph and the indexes once for this module."""
    missing = CorpusLayout(root=KNOWLEDGE_DIR).missing_sources()
    if missing:
        pytest.skip(f"corpus incomplete: {', '.join(source.value for source in missing)}")
    return RetrievalService.build(KNOWLEDGE_DIR)


def runtime_factory() -> RuntimeFactory:
    """Return a factory with every source of variation pinned."""
    return RuntimeFactory(
        now=lambda: datetime(2026, 7, 24, 9, 15, 30, tzinfo=UTC),
        new_id=lambda: FIXED_ID,
        timer=lambda: 0.0,
    )


def prepared(operation: ReasoningOperation, service: RetrievalService):
    """Return the package the pipeline is expected to build, over real retrieval."""
    if operation is ReasoningOperation.GENERATE:
        return ContextBuilder().build(
            operation.context_operation,
            rule=None,
            entities=None,
            mappings=None,
            retrieval=service.for_requirement(REQUIREMENT),
        )
    parsed = RuleParser().parse(RULE_TEXT)
    entities = EntityExtractor().extract(parsed)
    mappings = EntityMapper().map(entities)
    rule = rule_context_from_parsed(parsed)
    return ContextBuilder().build(
        operation.context_operation,
        rule=rule,
        entities=entities,
        mappings=mappings,
        retrieval=service.for_rule(rule, mappings),
    )


def request_for(operation: ReasoningOperation) -> EngineRequest:
    """Return a valid request for one operation."""
    if operation is ReasoningOperation.GENERATE:
        return EngineRequest(operation, user_id=USER, requirement=REQUIREMENT)
    return EngineRequest(
        operation, user_id=USER, rule_text=RULE_TEXT, rule_id=RULE_ID
    )


def pipeline_for(operation: ReasoningOperation, service: RetrievalService):
    """Return a pipeline over real retrieval, answering with a fake provider."""
    provider = fixtures.provider_returning([RESPONSES[operation](prepared(operation, service))])
    return Pipeline(
        engine=fixtures.engine_of(provider),
        retrieval=service,
        runtime=runtime_factory(),
    ), provider


# --------------------------------------------------------------- the retrieval leg


def test_the_service_assembles_and_answers(retrieval):
    parsed = RuleParser().parse(RULE_TEXT)
    entities = EntityExtractor().extract(parsed)
    mappings = EntityMapper().map(entities)
    result = retrieval.for_rule(rule_context_from_parsed(parsed), mappings)
    assert len(result) > 0
    assert result.items[0].chunk.parent_record_id


def test_the_identifier_seed_reaches_the_technique_in_the_real_corpus(retrieval):
    """The point of seeding with resolved identifiers: the ATT&CK record comes back."""
    parsed = RuleParser().parse(RULE_TEXT)
    entities = EntityExtractor().extract(parsed)
    mappings = EntityMapper().map(entities)
    assert "T1059.001" in [item.canonical_id for item in mappings.resolved]
    result = retrieval.for_rule(rule_context_from_parsed(parsed), mappings)
    assert KnowledgeSource.MITRE in {item.chunk.source for item in result.items}


def test_a_requirement_retrieves_over_the_same_corpus(retrieval):
    assert len(retrieval.for_requirement(REQUIREMENT)) > 0


def test_a_requirement_naming_a_technique_reaches_it_by_text_alone(retrieval):
    """Generate resolves nothing, so the lexical route is all it has."""
    result = retrieval.for_requirement(REQUIREMENT)
    assert KnowledgeSource.MITRE in {item.chunk.source for item in result.items}


def test_retrieval_is_deterministic_over_one_corpus(retrieval):
    first = retrieval.for_requirement(REQUIREMENT)
    second = retrieval.for_requirement(REQUIREMENT)
    assert [item.chunk.chunk_id for item in first.items] == [
        item.chunk.chunk_id for item in second.items
    ]


def test_the_index_is_built_once_and_reused(retrieval):
    """The service is module scoped, so a second query must not rebuild anything."""
    before = retrieval.settings
    retrieval.for_requirement(REQUIREMENT)
    assert retrieval.settings is before
    assert retrieval.settings == DEFAULT_SETTINGS


def test_the_corpus_is_never_written_to(retrieval):
    """Retrieval reads. Nothing under resources/knowledge may change."""
    layout = CorpusLayout(root=KNOWLEDGE_DIR)
    before = {
        source: layout.path_for(source).stat().st_mtime for source in layout.available_sources()
    }
    retrieval.for_requirement(REQUIREMENT)
    after = {
        source: layout.path_for(source).stat().st_mtime for source in layout.available_sources()
    }
    assert before == after


# ------------------------------------------------------------------ the whole chain


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_the_whole_pipeline_ends_in_a_contract_document(operation, retrieval):
    pipeline, provider = pipeline_for(operation, retrieval)
    document = pipeline.run(request_for(operation))
    assert document["analysis"]["analysisType"] == operation.value
    assert provider.calls == 1


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_every_document_is_json_serialisable_as_produced(operation, retrieval):
    pipeline, _ = pipeline_for(operation, retrieval)
    document = pipeline.run(request_for(operation))
    assert json.loads(json.dumps(document)) == document


@pytest.mark.parametrize("operation", list(ReasoningOperation), ids=lambda o: o.value)
def test_the_package_the_pipeline_builds_passes_its_own_validator(operation, retrieval):
    package = prepared(operation, retrieval)
    ContextValidator().validate(package).raise_if_invalid()


def test_the_real_package_carries_evidence_drawn_from_the_real_corpus(retrieval):
    package = prepared(ReasoningOperation.ANALYZE, retrieval)
    assert package.provenance is not None
    assert package.provenance.retrieval_items > 0
    assert package.provenance.sources_present


def test_no_uncertainty_or_citation_leaks_into_the_document(retrieval):
    for operation in ReasoningOperation:
        pipeline, _ = pipeline_for(operation, retrieval)
        encoded = json.dumps(pipeline.run(request_for(operation)))
        assert "uncertaint" not in encoded.lower()
        assert "item_id" not in encoded
