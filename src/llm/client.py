"""LLM client.

The package's entry point. Converts a rendered prompt into a request, runs it
through a provider under the configured retry policy, and logs the outcome.

The client holds no conversation state. Each call is independent, so the same
client can serve any number of operations.

Logging is restricted to provider, model, duration, token usage and finish
reason. Prompt text, runtime context, response text and credentials are never
logged. Retry warnings carry the failure's type and status code, never its
message, because provider messages can quote the request.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import final

from src.config.settings import ModelSettings
from src.prompts.prompt_models import RenderedPrompt

from .exceptions import LLMError
from .provider import LLMProvider
from .request import LLMRequest
from .response import LLMResponse
from .retry import RetryExecutor, RetryPolicy
from .types import ResponseFormat


@final
@dataclass(frozen=True, slots=True)
class LLMClient:
    """Executes rendered prompts against a provider."""

    provider: LLMProvider
    settings: ModelSettings
    executor: RetryExecutor
    logger: logging.Logger = field(repr=False)

    @classmethod
    def create(
        cls,
        provider: LLMProvider,
        settings: ModelSettings,
        *,
        sleep: Callable[[float], None] = time.sleep,
        logger: logging.Logger | None = None,
    ) -> LLMClient:
        """Build a client with a retry executor derived from configuration."""
        return cls(
            provider=provider,
            settings=settings,
            executor=RetryExecutor(policy=RetryPolicy.from_settings(settings), sleep=sleep),
            logger=logger if logger is not None else logging.getLogger(__name__),
        )

    def execute(
        self,
        prompt: RenderedPrompt,
        *,
        response_format: ResponseFormat = ResponseFormat.JSON,
    ) -> LLMResponse:
        """Execute a rendered prompt and return the provider's response."""
        request = LLMRequest.from_rendered_prompt(
            prompt,
            self.settings,
            response_format=response_format,
        )
        return self.execute_request(request)

    def execute_request(self, request: LLMRequest) -> LLMResponse:
        """Execute an already built request under the retry policy."""
        response = self.executor.call(
            lambda: self.provider.generate(request),
            lambda attempt, error, delay: self._log_retry(request, attempt, error, delay),
        )
        self._log_success(request, response)
        return response

    def _log_success(self, request: LLMRequest, response: LLMResponse) -> None:
        """Log the completed call using only non-sensitive fields."""
        usage = response.usage
        self.logger.info(
            "llm call completed operation=%s provider=%s model=%s duration=%.3fs "
            "finish_reason=%s prompt_tokens=%d completion_tokens=%d total_tokens=%d",
            request.operation,
            response.provider,
            response.model,
            response.duration_seconds,
            response.finish_reason.value,
            usage.prompt_tokens,
            usage.completion_tokens,
            usage.total_tokens,
        )

    def _log_retry(
        self,
        request: LLMRequest,
        attempt: int,
        error: LLMError,
        delay: float,
    ) -> None:
        """Log a transient failure before waiting to retry.

        Records the failure's type and status code only. Provider messages can
        echo request content, so they are not logged.
        """
        self.logger.warning(
            "llm call failed, retrying operation=%s provider=%s model=%s "
            "attempt=%d/%d error=%s status=%s delay=%.2fs",
            request.operation,
            self.provider.name,
            request.parameters.model,
            attempt,
            self.executor.policy.max_attempts,
            type(error).__name__,
            getattr(error, "status_code", None),
            delay,
        )
