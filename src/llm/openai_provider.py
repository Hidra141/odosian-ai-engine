"""OpenAI-compatible adapter.

Covers OpenAI, Gemini (OpenAI-compat mode), Groq, Together AI, Ollama, vLLM,
and any endpoint that speaks the OpenAI chat-completions contract.

The API key and base URL arrive as plain strings from the HTTP layer — the
server that wraps this library receives them per-request and never persists
them. The key is stored on the SDK client object and never placed in an
exception message, a log record, or a repr.
"""

from __future__ import annotations

import json
import time
from typing import Any, Final, final

import openai

from .exceptions import (
    LLMAuthenticationError,
    LLMConnectionError,
    LLMError,
    LLMInvalidResponseError,
    LLMModelUnavailableError,
    LLMProviderError,
    LLMRateLimitError,
    LLMServiceUnavailableError,
    LLMTimeoutError,
)
from .request import LLMRequest
from .response import LLMResponse, TokenUsage
from .types import FinishReason, ResponseFormat

PROVIDER_NAME: Final[str] = "openai_compatible"

_MAX_ERROR_DETAIL: Final[int] = 200


@final
class OpenAICompatibleProvider:
    """Executes requests against any OpenAI-compatible endpoint."""

    __slots__ = ("_client", "_provider_name", "_model_name")

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model_name: str,
        provider_name: str = PROVIDER_NAME,
    ) -> None:
        self._client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self._provider_name = provider_name
        self._model_name = model_name

    @property
    def name(self) -> str:
        return self._provider_name

    def generate(self, request: LLMRequest) -> LLMResponse:
        messages = _build_messages(request)
        params = request.parameters
        model = self._model_name or params.model

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": params.temperature,
            "top_p": params.top_p,
            "max_tokens": params.max_output_tokens,
            "timeout": params.timeout_seconds,
        }

        if request.response_format is ResponseFormat.JSON:
            if request.has_schema:
                kwargs["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "response",
                        "schema": dict(request.response_json_schema),
                        "strict": True,
                    },
                }
            else:
                kwargs["response_format"] = {"type": "json_object"}

        started = time.perf_counter()
        try:
            raw = self._client.chat.completions.create(**kwargs)
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise _map_error(error, model, self._provider_name) from error
        duration = time.perf_counter() - started
        return _build_response(raw, model, self._provider_name, duration)


def _build_messages(request: LLMRequest) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    if request.has_system:
        messages.append({"role": "system", "content": request.system})
    messages.append({"role": "user", "content": request.instruction})
    return messages


def _build_response(
    raw: Any, model: str, provider_name: str, duration: float
) -> LLMResponse:
    choice = raw.choices[0] if raw.choices else None
    if choice is None:
        raise LLMInvalidResponseError(
            "provider returned no choices",
            provider=provider_name,
            model=model,
        )
    text = choice.message.content or ""
    finish = FinishReason.from_provider(choice.finish_reason)
    usage = _extract_usage(raw)
    return LLMResponse(
        text=text,
        provider=provider_name,
        model=raw.model or model,
        finish_reason=finish,
        usage=usage,
        duration_seconds=duration,
    )


def _extract_usage(raw: Any) -> TokenUsage:
    usage = getattr(raw, "usage", None)
    if usage is None:
        return TokenUsage.unknown()
    return TokenUsage(
        prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
        completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        total_tokens=getattr(usage, "total_tokens", 0) or 0,
    )


def _map_error(error: BaseException, model: str, provider_name: str) -> LLMError:
    if isinstance(error, LLMError):
        return error

    detail = _safe_detail(error)

    if isinstance(error, openai.AuthenticationError):
        return LLMAuthenticationError(
            "provider rejected the credentials",
            provider=provider_name,
            model=model,
            status_code=getattr(error, "status_code", 401),
        )
    if isinstance(error, openai.RateLimitError):
        return LLMRateLimitError(
            "provider is rate limiting the request",
            provider=provider_name,
            model=model,
            status_code=getattr(error, "status_code", 429),
        )
    if isinstance(error, openai.NotFoundError):
        return LLMModelUnavailableError(
            f"model {model!r} is unavailable or not accessible",
            provider=provider_name,
            model=model,
            status_code=getattr(error, "status_code", 404),
        )
    if isinstance(error, openai.InternalServerError):
        return LLMServiceUnavailableError(
            f"provider reported an internal error: {detail}",
            provider=provider_name,
            model=model,
            status_code=getattr(error, "status_code", 500),
        )
    if isinstance(error, openai.APITimeoutError):
        return LLMTimeoutError(
            "request timed out",
            provider=provider_name,
            model=model,
        )
    if isinstance(error, openai.APIConnectionError):
        return LLMConnectionError(
            f"could not reach the provider: {detail}",
            provider=provider_name,
            model=model,
        )
    if isinstance(error, openai.APIStatusError):
        code = getattr(error, "status_code", None)
        if code is not None and 500 <= code < 600:
            return LLMServiceUnavailableError(
                f"provider reported an internal error: {detail}",
                provider=provider_name,
                model=model,
                status_code=code,
            )
        return LLMProviderError(
            f"provider call failed ({type(error).__name__}): {detail}",
            provider=provider_name,
            model=model,
            status_code=code,
        )

    kind = type(error).__name__.lower()
    if isinstance(error, TimeoutError) or "timeout" in kind:
        return LLMTimeoutError(
            "request timed out",
            provider=provider_name,
            model=model,
        )
    if "connect" in kind or "network" in kind:
        return LLMConnectionError(
            f"could not reach the provider: {detail}",
            provider=provider_name,
            model=model,
        )
    return LLMProviderError(
        f"provider call failed ({type(error).__name__}): {detail}",
        provider=provider_name,
        model=model,
    )


def _safe_detail(error: BaseException) -> str:
    text = str(error).strip().replace("\n", " ")
    if len(text) <= _MAX_ERROR_DETAIL:
        return text or type(error).__name__
    return f"{text[:_MAX_ERROR_DETAIL]}..."
