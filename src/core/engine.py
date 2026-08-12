"""Reasoning engine.

The orchestrator: context package in, typed reasoning result out.

    ContextPackage
        -> prompt variables            (this layer's view of the package)
        -> RenderedPrompt              (Stage-06)
        -> LLMRequest, execution       (Stage-07, under its own retry policy)
        -> strict JSON decode          (Stage-07)
        -> schema check                (this layer)
        -> typed result                (this layer)
        -> reasoning validation        (this layer)

The engine owns the sequence and nothing else. It does not parse rules, extract
entities, retrieve knowledge, walk the graph or build context: those stages are
finished before it is called. It does not talk to a provider either — it holds
an :class:`~src.llm.client.LLMClient` and calls it, so the only module in the
process that knows which provider is in use is the adapter the caller supplied.

Failure keeps its origin. A provider that rate limits raises Stage-07's
``LLMRateLimitError`` after Stage-07's retry policy has given up; a body that is
not JSON raises Stage-07's ``LLMInvalidJSONError``; a template that cannot render
raises this layer's :class:`~src.core.exceptions.PromptRenderingError` chained to
the prompt error beneath it. Nothing is re-raised as a generic engine failure,
and nothing is retried here — Stage-07 already decided what a transient failure
is, and a second retry loop wrapped around the first would multiply the attempts
the configuration asked for.

Everything except the model's own answer is deterministic. The same package
produces the same prompt, byte for byte, on every run.

Logging follows Stage-07's rule: the operation, the provider, the model, the
shape of the result. Never a prompt, never context, never a response body, never
a credential.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, TypeVar, final

from src.config.settings import EngineConfig, ModelSettings
from src.llm.client import LLMClient
from src.llm.provider import LLMProvider
from src.llm.response import LLMResponse
from src.llm.types import ResponseFormat
from src.prompts.exceptions import PromptError
from src.prompts.prompt_builder import PromptBuilder
from src.prompts.prompt_models import PromptRef, PromptRequest, RenderedPrompt
from src.prompts.prompt_repository import PromptRepository
from src.prompts.types import DEFAULT_SYSTEM_NAME, PromptScope

from .context_view import ContextView
from .exceptions import PromptRenderingError, ReasoningValidationError
from .models import (
    AnalyzeRequest,
    AnalyzeResult,
    EnhanceRequest,
    EnhanceResult,
    GenerateRequest,
    GenerateResult,
    OperationResult,
    ReasoningRequest,
)
from .output_format import json_schema_for
from .response_parser import ResponseParser
from .types import ReasoningOperation
from .validation import ReasoningValidator

SHARED_PROMPT_REFS: Final[tuple[PromptRef, ...]] = (
    PromptRef(PromptScope.SHARED, DEFAULT_SYSTEM_NAME),
    PromptRef(PromptScope.SHARED, "output"),
    PromptRef(PromptScope.SHARED, "safety"),
    PromptRef(PromptScope.SHARED, "glossary"),
)
"""The shared templates, in the order Prompt Specification v1.0 section 7 assembles them.

Stage-06 renders ``shared_refs`` first and the system reference last, and every
one of them into the system part. Passing the four this way reproduces
``system + output + safety + glossary`` exactly. The last is passed as the
system reference because leaving it unset would make Stage-06 look for
``<operation>/system``, a template the ``prompts/`` tree deliberately does not
have: identity is shared, not per operation.
"""

_ResultT = TypeVar("_ResultT", bound=OperationResult)


@final
@dataclass(frozen=True, slots=True)
class ReasoningEngine:
    """Runs one reasoning operation end to end."""

    client: LLMClient
    builder: PromptBuilder
    view: ContextView = field(default_factory=ContextView)
    parser: ResponseParser = field(default_factory=ResponseParser)
    validator: ReasoningValidator = field(default_factory=ReasoningValidator)
    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger(__name__), repr=False
    )

    @classmethod
    def create(
        cls,
        provider: LLMProvider,
        config: EngineConfig,
        *,
        sleep: Callable[[float], None] = time.sleep,
        logger: logging.Logger | None = None,
    ) -> ReasoningEngine:
        """Build an engine from a provider and the resolved configuration.

        The provider arrives already constructed. The engine never reads a
        secret, never builds a client for a named provider, and never learns
        which provider it is holding.
        """
        return cls.of(
            provider=provider,
            settings=config.model,
            prompts_dir=config.paths.prompts_dir,
            sleep=sleep,
            logger=logger,
        )

    @classmethod
    def of(
        cls,
        *,
        provider: LLMProvider,
        settings: ModelSettings,
        prompts_dir: Path,
        sleep: Callable[[float], None] = time.sleep,
        logger: logging.Logger | None = None,
    ) -> ReasoningEngine:
        """Build an engine from its parts, for a caller without a full configuration."""
        resolved = logger if logger is not None else logging.getLogger(__name__)
        return cls(
            client=LLMClient.create(provider, settings, sleep=sleep, logger=resolved),
            builder=PromptBuilder(repository=PromptRepository(root=prompts_dir)),
            logger=resolved,
        )

    def analyze(self, request: AnalyzeRequest) -> AnalyzeResult:
        """Assess an existing rule against its context package."""
        return self._typed(self.run(request.as_reasoning_request()), AnalyzeResult)

    def enhance(self, request: EnhanceRequest) -> EnhanceResult:
        """Improve an existing rule and account for every change."""
        return self._typed(self.run(request.as_reasoning_request()), EnhanceResult)

    def generate(self, request: GenerateRequest) -> GenerateResult:
        """Write a rule satisfying a stated detection requirement."""
        return self._typed(self.run(request.as_reasoning_request()), GenerateResult)

    def run(self, request: ReasoningRequest) -> OperationResult:
        """Execute one operation end to end."""
        request.validate()
        prompt = self.build_prompt(request)
        response = self.client.execute(
            prompt,
            response_format=ResponseFormat.JSON,
            response_json_schema=json_schema_for(request.operation),
        )
        result = self.parser.parse(request.operation, response)
        self.validator.validate(result, request).raise_if_invalid()
        self._log_result(request.operation, response, result)
        return result

    def build_prompt(self, request: ReasoningRequest) -> RenderedPrompt:
        """Render the prompt for one request.

        Separated from :meth:`run` so a caller can inspect exactly what would be
        sent without sending it, which is also how the determinism of this layer
        is tested.
        """
        prompt_request = PromptRequest(
            operation=request.operation.prompt_operation,
            context=self.view.prompt_context(request),
            shared_refs=SHARED_PROMPT_REFS[:-1],
            system_ref=SHARED_PROMPT_REFS[-1],
        )
        try:
            return self.builder.build(prompt_request)
        except PromptError as error:
            raise PromptRenderingError(request.operation.value, str(error)) from error

    def _typed(self, result: OperationResult, expected: type[_ResultT]) -> _ResultT:
        """Return a result narrowed to the type its operation must produce."""
        if not isinstance(result, expected):
            raise ReasoningValidationError(
                result.operation.value,
                [
                    "result_type_mismatch: expected "
                    f"{expected.__name__}, got {type(result).__name__}"
                ],
            )
        return result

    def _log_result(
        self,
        operation: ReasoningOperation,
        response: LLMResponse,
        result: OperationResult,
    ) -> None:
        """Log the shape of a completed operation, and nothing it contains."""
        self.logger.info(
            "reasoning completed operation=%s provider=%s model=%s finish_reason=%s "
            "findings=%d recommendations=%d uncertainties=%d confidence=%.2f",
            operation.value,
            response.provider,
            response.model,
            response.finish_reason.value,
            len(result.findings),
            len(result.recommendations),
            len(result.uncertainties),
            result.confidence,
        )
