"""The pipeline.

Every stage from a caller's request to a contract document, in one place.

    EngineRequest -> parse -> extract -> map        (analyze, enhance only)
                  -> retrieve                        (Stage-13)
                  -> build context                   (Stage-14)
                  -> validate context                (Stage-14)
                  -> reason                          (Stage-15)
                  -> validate result                 (Stage-16)
                  -> format                          (Stage-17)

Analyze, enhance and generate are three paths through one pipeline rather than
three pipelines. The first two differ only in which engine method runs at the
end; generate differs before that too, and takes a shorter path. It is asked
about a requirement no rule yet satisfies, so there is nothing to parse, nothing
to extract and nothing to map, and none of those three stages is called.

The context is validated before the provider is. A package that fails its own
validator would be paid for and then refused, so the order here means a caller
never spends a token on evidence the engine would not accept.

Nothing is caught, wrapped or retried. Every stage raises its own errors and
they arrive at the caller as that stage raised them: a rule that will not parse
is a parser error, a corpus that will not load is a knowledge error, a result
Stage-16 refuses is that refusal. Stage-07 already decided what a transient
provider failure is and retried it; a second loop wrapped around the first would
multiply the attempts the configuration asked for.

The provider arrives constructed. This layer holds an engine and never learns
which backend is behind it, which is what lets every test here run without a
credential.

Logging follows the rule the lower stages set: the operation, the provider, the
model, the shape of the run. Never a rule, never a requirement, never context,
never a response, never a credential, and never the account that asked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, assert_never, final

from src.config.settings import EngineConfig
from src.context.context_builder import ContextBuilder, rule_context_from_parsed
from src.context.models import ContextPackage
from src.context.validation import ContextValidator
from src.core.engine import ReasoningEngine
from src.core.models import (
    AnalyzeRequest,
    EnhanceRequest,
    GenerateRequest,
    OperationResult,
)
from src.core.types import ReasoningOperation
from src.entities.extractor import EntityExtractor
from src.formatter.formatter import format_result
from src.llm.provider import LLMProvider
from src.mapping.entity_mapper import EntityMapper
from src.parser.parser import RuleParser
from src.validation.engine import ValidationEngine

from .requests import EngineRequest
from .retrieval import RetrievalService
from .runtime import RuntimeFactory


@final
@dataclass(frozen=True, slots=True)
class Pipeline:
    """Runs one request from raw input to its contract document."""

    engine: ReasoningEngine
    retrieval: RetrievalService
    runtime: RuntimeFactory = field(default_factory=RuntimeFactory)
    parser: RuleParser = field(default_factory=RuleParser)
    extractor: EntityExtractor = field(default_factory=EntityExtractor)
    mapper: EntityMapper = field(default_factory=EntityMapper)
    builder: ContextBuilder = field(default_factory=ContextBuilder)
    context_validator: ContextValidator = field(default_factory=ContextValidator)
    validator: ValidationEngine = field(default_factory=ValidationEngine)
    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger(__name__), repr=False
    )

    @classmethod
    def create(
        cls,
        config: EngineConfig,
        provider: LLMProvider,
        *,
        retrieval: RetrievalService | None = None,
        runtime: RuntimeFactory | None = None,
        logger: logging.Logger | None = None,
    ) -> Pipeline:
        """Build a pipeline from the resolved configuration and a constructed provider.

        The retriever is assembled here unless one is supplied, which reads
        every dataset once. Build a pipeline once and keep it; building one per
        request would index the corpus per request.
        """
        resolved_logger = logger if logger is not None else logging.getLogger(__name__)
        return cls(
            engine=ReasoningEngine.create(provider, config, logger=resolved_logger),
            retrieval=(
                retrieval
                if retrieval is not None
                else RetrievalService.build(config.paths.knowledge_dir)
            ),
            runtime=runtime if runtime is not None else RuntimeFactory(),
            logger=resolved_logger,
        )

    def run(self, request: EngineRequest) -> dict[str, Any]:
        """Run one request end to end and return the contract document."""
        request.validate()
        started = self.runtime.start()
        package, input_query = self._prepare(request)
        self.context_validator.validate(package).raise_if_invalid()
        result = self._reason(request, package)
        accepted = self.validator.validate_or_raise(result, package)
        envelope = self.runtime.create(request, started=started, input_query=input_query)
        self._log(accepted, package, envelope.latency_ms)
        return format_result(accepted, envelope)

    def _prepare(self, request: EngineRequest) -> tuple[ContextPackage, str]:
        """Run every stage before reasoning, and return the package and its query."""
        if request.is_rule_operation:
            return self._prepare_from_rule(request)
        return self._prepare_from_requirement(request)

    def _prepare_from_rule(self, request: EngineRequest) -> tuple[ContextPackage, str]:
        """Prepare an analyze or enhance package from the supplied rule."""
        parsed = self.parser.parse(request.rule_text)
        entities = self.extractor.extract(parsed)
        mappings = self.mapper.map(entities)
        rule = rule_context_from_parsed(parsed)
        found = self.retrieval.for_rule(rule, mappings)
        package = self.builder.build(
            request.operation.context_operation,
            rule=rule,
            entities=entities,
            mappings=mappings,
            retrieval=found,
        )
        return package, rule.query

    def _prepare_from_requirement(self, request: EngineRequest) -> tuple[ContextPackage, str]:
        """Prepare a generate package from the requirement alone.

        The parser, the extractor and the mapper are not called. There is no
        rule to parse, and a requirement is not one.
        """
        found = self.retrieval.for_requirement(request.requirement)
        package = self.builder.build(
            request.operation.context_operation,
            rule=None,
            entities=None,
            mappings=None,
            retrieval=found,
        )
        return package, request.requirement

    def _reason(self, request: EngineRequest, package: ContextPackage) -> OperationResult:
        """Dispatch to the engine method the operation names."""
        match request.operation:
            case ReasoningOperation.ANALYZE:
                return self.engine.analyze(AnalyzeRequest(package=package))
            case ReasoningOperation.ENHANCE:
                return self.engine.enhance(EnhanceRequest(package=package))
            case ReasoningOperation.GENERATE:
                return self.engine.generate(
                    GenerateRequest(package=package, requirement=request.requirement)
                )
            case _:  # pragma: no cover - the enum states three operations
                assert_never(request.operation)

    def _log(
        self,
        result: OperationResult,
        package: ContextPackage,
        latency_ms: int,
    ) -> None:
        """Log the shape of one completed run, and nothing it carried."""
        provenance = package.provenance
        self.logger.info(
            "pipeline completed operation=%s provider=%s model=%s retrieval_items=%d "
            "context_items=%d latency_ms=%d",
            result.operation.value,
            result.provenance.provider,
            result.provenance.model,
            provenance.retrieval_items if provenance is not None else 0,
            sum(len(section.items) for section in package.sections),
            latency_ms,
        )
