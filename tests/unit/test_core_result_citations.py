"""Stage-15 result citations.

``cited_item_ids`` on every result type.

The accessor is the only place where a subclass reaches back into
:class:`ReasoningResult`. That reach-back is easy to write in a way that raises
only for the subclasses — ``dataclass(slots=True)`` replaces the class object,
so zero-argument ``super()`` inside one of these methods resolves against a
class the instance is no longer an instance of. These tests call the accessor on
all three result types, which is what the earlier suites never did.
"""

from __future__ import annotations

import pytest

from src.context.types import ContextOperation
from src.core.models import (
    AnalyzeRequest,
    EnhanceRequest,
    GenerateRequest,
    ReasoningProvenance,
)
from src.core.types import ReasoningOperation
from src.knowledge.models.types import KnowledgeSource
from src.llm.types import FinishReason
from tests.fixtures import stage15 as fixtures


def citation(item_id: str, source: str, detail: str) -> dict[str, str]:
    """Return a citation of a supplied item that carries no identifier."""
    return {"item_id": item_id, "source": source, "identifier": "", "detail": detail}


def run(operation: ReasoningOperation, payload, package):
    """Run one operation against a fake provider and return the typed result."""
    engine = fixtures.engine_of(fixtures.provider_returning([payload]))
    match operation:
        case ReasoningOperation.ANALYZE:
            return engine.analyze(AnalyzeRequest(package=package))
        case ReasoningOperation.ENHANCE:
            return engine.enhance(EnhanceRequest(package=package))
        case _:
            return engine.generate(GenerateRequest(package=package))


CASES = (
    (ReasoningOperation.ANALYZE, ContextOperation.ANALYZE, fixtures.analyze_response),
    (ReasoningOperation.ENHANCE, ContextOperation.ENHANCE, fixtures.enhance_response),
    (ReasoningOperation.GENERATE, ContextOperation.GENERATE, fixtures.generate_response),
)


@pytest.mark.parametrize(
    ("operation", "context_operation", "response_of"),
    CASES,
    ids=[item[0].value for item in CASES],
)
def test_cited_item_ids_returns_the_cited_items(operation, context_operation, response_of):
    package = fixtures.context_package(context_operation)
    result = run(operation, response_of(package), package)
    cited = result.cited_item_ids()
    assert cited == (fixtures.item_id_of(package, KnowledgeSource.MITRE),)
    assert set(cited) <= {item.item_id for item in package.items}


def test_analyze_collects_citations_from_every_finding():
    package = fixtures.context_package()
    mitre = fixtures.item_id_of(package, KnowledgeSource.MITRE)
    lolbas = fixtures.item_id_of(package, KnowledgeSource.LOLBAS)
    payload = fixtures.analyze_response(package)
    payload["findings"][0]["evidence"].append(citation(lolbas, "lolbas", "accepted abbreviations"))
    result = run(ReasoningOperation.ANALYZE, payload, package)
    assert result.cited_item_ids() == (mitre, lolbas)


def test_enhance_collects_citations_from_findings_and_changes():
    package = fixtures.context_package(ContextOperation.ENHANCE)
    mitre = fixtures.item_id_of(package, KnowledgeSource.MITRE)
    lolbas = fixtures.item_id_of(package, KnowledgeSource.LOLBAS)
    elastic = fixtures.item_id_of(package, KnowledgeSource.ELASTIC)
    payload = fixtures.enhance_response(package)
    payload["findings"][0]["evidence"].append(citation(lolbas, "lolbas", "flag spellings"))
    payload["changes"][0]["evidence"] = [citation(elastic, "elastic", "a rule matching all forms")]
    result = run(ReasoningOperation.ENHANCE, payload, package)
    assert result.cited_item_ids() == (mitre, lolbas, elastic)


def test_generate_collects_citations_from_findings_rationale_and_mappings():
    package = fixtures.context_package(ContextOperation.GENERATE)
    mitre = fixtures.item_id_of(package, KnowledgeSource.MITRE)
    ecs = fixtures.item_id_of(package, KnowledgeSource.ECS)
    lolbas = fixtures.item_id_of(package, KnowledgeSource.LOLBAS)
    payload = fixtures.generate_response(package)
    payload["rationale"][0]["evidence"] = [citation(ecs, "ecs", "the field exists")]
    payload["mappings"][0]["evidence"] = [citation(lolbas, "lolbas", "the technique is observed")]
    result = run(ReasoningOperation.GENERATE, payload, package)
    assert result.cited_item_ids() == (mitre, ecs, lolbas)


@pytest.mark.parametrize(
    ("operation", "context_operation", "response_of"),
    CASES,
    ids=[item[0].value for item in CASES],
)
def test_a_repeated_citation_is_reported_once(operation, context_operation, response_of):
    package = fixtures.context_package(context_operation)
    mitre = fixtures.item_id_of(package, KnowledgeSource.MITRE)
    payload = response_of(package)
    payload["findings"][0]["evidence"].append(citation(mitre, "mitre", "the same item again"))
    result = run(operation, payload, package)
    assert result.cited_item_ids() == (mitre,)


@pytest.mark.parametrize(
    ("operation", "context_operation", "response_of"),
    CASES,
    ids=[item[0].value for item in CASES],
)
def test_a_result_citing_nothing_returns_no_ids(operation, context_operation, response_of):
    package = fixtures.context_package(context_operation)
    payload = response_of(package)
    payload["findings"][0]["evidence"] = []
    if "changes" in payload:
        payload["changes"][0]["evidence"] = []
    if "rationale" in payload:
        payload["rationale"][0]["evidence"] = []
        payload["mappings"] = []
    result = run(operation, payload, package)
    assert result.cited_item_ids() == ()


@pytest.mark.parametrize(
    ("operation", "context_operation", "response_of"),
    CASES,
    ids=[item[0].value for item in CASES],
)
def test_a_result_with_no_findings_at_all_returns_no_ids(
    operation, context_operation, response_of
):
    package = fixtures.context_package(context_operation)
    payload = response_of(package)
    payload["findings"] = []
    payload["recommendations"] = []
    if "changes" in payload:
        payload["changes"][0]["addresses"] = []
        payload["changes"][0]["evidence"] = []
    if "rationale" in payload:
        payload["rationale"][0]["evidence"] = []
        payload["mappings"] = []
    result = run(operation, payload, package)
    assert result.findings == ()
    assert result.cited_item_ids() == ()


@pytest.mark.parametrize(
    ("operation", "context_operation", "response_of"),
    CASES,
    ids=[item[0].value for item in CASES],
)
def test_the_accessor_is_stable_across_calls(operation, context_operation, response_of):
    package = fixtures.context_package(context_operation)
    result = run(operation, response_of(package), package)
    assert result.cited_item_ids() == result.cited_item_ids()


def test_results_built_directly_also_answer_the_accessor():
    """A result constructed without the parser must behave the same way."""
    package = fixtures.context_package(ContextOperation.ENHANCE)
    parsed = run(ReasoningOperation.ENHANCE, fixtures.enhance_response(package), package)
    rebuilt = type(parsed)(
        operation=parsed.operation,
        summary=parsed.summary,
        findings=(),
        recommendations=(),
        confidence=parsed.confidence,
        metadata=parsed.metadata,
        uncertainties=parsed.uncertainties,
        provenance=ReasoningProvenance(
            operation=parsed.operation,
            provider="fake",
            model="fake-model",
            finish_reason=FinishReason.STOP,
            usage=parsed.provenance.usage,
        ),
        original_rule=parsed.original_rule,
        enhanced_rule=parsed.enhanced_rule,
        changes=parsed.changes,
    )
    assert rebuilt.cited_item_ids() == tuple(
        dict.fromkeys(item.item_id for change in parsed.changes for item in change.evidence)
    )
