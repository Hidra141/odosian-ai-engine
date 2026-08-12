"""Stage-15 end to end.

A real Sigma rule through the real Stage-08, Stage-09, Stage-10 and Stage-14
objects, into the reasoning engine, out as a typed result.

Retrieval is supplied as a fixture rather than run, because running it would
load the knowledge corpus and build the index — Stage-13's own tests cover that,
and no test here reads a dataset. Everything else on the path is the shipped
code.
"""

from __future__ import annotations

from src.context.context_builder import ContextBuilder, rule_context_from_parsed
from src.context.types import ContextOperation
from src.context.validation import ContextValidator
from src.core.engine import ReasoningEngine
from src.core.models import AnalyzeRequest, EnhanceRequest, GenerateRequest, ReasoningRequest
from src.core.types import ReasoningOperation
from src.entities.extractor import EntityExtractor
from src.mapping.entity_mapper import EntityMapper
from src.parser.parser import RuleParser
from tests.fixtures import stage15 as fixtures


def pipeline_package(operation=ContextOperation.ANALYZE):
    """Run the frozen stages and return the package Stage-15 consumes."""
    parsed = RuleParser().parse(fixtures.RULE_TEXT)
    entities = EntityExtractor().extract(parsed)
    mappings = EntityMapper().map(entities)
    package = ContextBuilder().build(
        operation,
        rule=parsed,
        entities=entities,
        mappings=mappings,
        retrieval=fixtures.retrieval_result(),
    )
    ContextValidator().validate(package).raise_if_invalid()
    return parsed, package


def test_a_parsed_rule_reaches_a_typed_analyze_result():
    parsed, package = pipeline_package()
    assert rule_context_from_parsed(parsed).title == "Suspicious PowerShell Encoded Command"

    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    result = fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))

    assert result.operation is ReasoningOperation.ANALYZE
    assert result.summary
    assert result.findings[0].category.value == "brittleness"
    assert result.cited_item_ids()
    assert {entry.identifier for entry in result.uncertainties} == {"T1562", "TA0011", "M1013"}


def test_the_pipeline_carries_the_corpus_gaps_all_the_way_to_the_result():
    _, package = pipeline_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    result = fixtures.engine_of(provider).analyze(AnalyzeRequest(package=package))

    by_identifier = {entry.identifier: entry for entry in result.uncertainties}
    assert by_identifier["T1562"].status.value == "unresolved"
    assert by_identifier["TA0011"].status.value == "unresolved"
    assert by_identifier["M1013"].status.value == "ambiguous"
    assert by_identifier["M1013"].candidates == ("enterprise:M1013", "mobile:M1013")


def test_enhance_and_generate_run_over_the_same_pipeline():
    _, enhance_package = pipeline_package(ContextOperation.ENHANCE)
    enhance_provider = fixtures.provider_returning(
        [fixtures.enhance_response(enhance_package)]
    )
    enhanced = fixtures.engine_of(enhance_provider).enhance(
        EnhanceRequest(package=enhance_package)
    )
    assert enhanced.enhanced_rule.parser_language.value == "kuery"
    assert enhanced.changes[0].addresses == ("F1",)

    _, generate_package = pipeline_package(ContextOperation.GENERATE)
    generate_provider = fixtures.provider_returning(
        [fixtures.generate_response(generate_package)]
    )
    generated = fixtures.engine_of(generate_provider).generate(
        GenerateRequest(package=generate_package)
    )
    assert generated.generated_rule.query
    assert generated.mappings[0].support.value == "supported"


def test_the_same_package_renders_the_same_prompt_every_time():
    _, first_package = pipeline_package()
    _, second_package = pipeline_package()
    engine = fixtures.engine_of(fixtures.provider_returning([]))

    first = engine.build_prompt(ReasoningRequest(ReasoningOperation.ANALYZE, first_package))
    second = engine.build_prompt(ReasoningRequest(ReasoningOperation.ANALYZE, second_package))

    assert first.system == second.system
    assert first.instruction == second.instruction
    assert first.variables == second.variables


def test_the_same_response_produces_an_identical_result_structure():
    _, package = pipeline_package()
    payload = fixtures.analyze_response(package)

    first = fixtures.engine_of(fixtures.provider_returning([payload])).analyze(
        AnalyzeRequest(package=package)
    )
    second = fixtures.engine_of(fixtures.provider_returning([payload])).analyze(
        AnalyzeRequest(package=package)
    )

    assert first == second
    assert first.provenance == second.provenance


def test_the_prompt_is_assembled_in_the_specified_order():
    _, package = pipeline_package()
    engine = fixtures.engine_of(fixtures.provider_returning([]))
    prompt = engine.build_prompt(ReasoningRequest(ReasoningOperation.ANALYZE, package))

    names = [segment.ref.name for segment in prompt.segments]
    assert names == ["system", "output", "safety", "glossary", "instruction"]
    assert prompt.system.index("# Identity") < prompt.system.index("# Output contract")
    assert prompt.system.index("# Output contract") < prompt.system.index("# Grounding")
    assert prompt.system.index("# Grounding") < prompt.system.index("# Glossary")
    assert "Operation: `analyze`" in prompt.instruction


def test_the_engine_can_be_built_from_a_provider_and_settings_alone():
    _, package = pipeline_package()
    provider = fixtures.provider_returning([fixtures.analyze_response(package)])
    engine = ReasoningEngine.of(
        provider=provider,
        settings=fixtures.model_settings(),
        prompts_dir=fixtures.PROMPTS_DIR,
        sleep=lambda _: None,
    )
    assert engine.analyze(AnalyzeRequest(package=package)).confidence == 0.72
