"""Anthropic adapter.

Covers Anthropic's Claude API. Maps the engine's provider-neutral request into
the Anthropic messages API, and every SDK exception into this package's
hierarchy.

Anthropic has no native JSON mode. When the request asks for JSON, the
instruction is appended with a directive to respond only in valid JSON.
"""

from __future__ import annotations

import time
from typing import Any, Final, final

import anthropic

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

PROVIDER_NAME: Final[str] = "anthropic"

_MAX_ERROR_DETAIL: Final[int] = 200

_JSON_INSTRUCTION_SUFFIX: Final[str] = (
    "\n\nIMPORTANT: You MUST respond with valid JSON only. "
    "Do not include any text before or after the JSON object. "
    "Do not use markdown code fences. Output raw JSON."
)


@final
class AnthropicProvider:
    """Executes requests against the Anthropic messages API."""

    __slots__ = ("_client", "_model_name")

    def __init__(self, *, api_key: str, model_name: str) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model_name = model_name

    @property
    def name(self) -> str:
        return PROVIDER_NAME

    def generate(self, request: LLMRequest) -> LLMResponse:
        params = request.parameters
        model = self._model_name or params.model

        instruction = request.instruction
        if request.response_format is ResponseFormat.JSON:
            instruction = instruction + _JSON_INSTRUCTION_SUFFIX

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": instruction}],
            "max_tokens": params.max_output_tokens,
            "temperature": params.temperature,
            "top_p": params.top_p,
        }

        if request.has_system:
            kwargs["system"] = request.system

        started = time.perf_counter()
        try:
            raw = self._client.messages.create(**kwargs)
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise _map_error(error, model) from error
        duration = time.perf_counter() - started
        return _build_response(raw, model, duration)


def _build_response(raw: Any, model: str, duration: float) -> LLMResponse:
    text = ""
    for block in raw.content:
        if getattr(block, "type", None) == "text":
            text += getattr(block, "text", "")

    if not text:
        raise LLMInvalidResponseError(
            "provider returned no text content",
            provider=PROVIDER_NAME,
            model=model,
        )

    finish = _map_stop_reason(raw.stop_reason)
    usage = _extract_usage(raw)

    return LLMResponse(
        text=text,
        provider=PROVIDER_NAME,
        model=raw.model or model,
        finish_reason=finish,
        usage=usage,
        duration_seconds=duration,
    )


def _map_stop_reason(reason: str | None) -> FinishReason:
    if reason is None:
        return FinishReason.UNKNOWN
    mapping = {
        "end_turn": FinishReason.STOP,
        "stop_sequence": FinishReason.STOP,
        "max_tokens": FinishReason.MAX_TOKENS,
    }
    return mapping.get(reason, FinishReason.UNKNOWN)


def _extract_usage(raw: Any) -> TokenUsage:
    usage = getattr(raw, "usage", None)
    if usage is None:
        return TokenUsage.unknown()
    input_tokens = getattr(usage, "input_tokens", 0) or 0
    output_tokens = getattr(usage, "output_tokens", 0) or 0
    return TokenUsage(
        prompt_tokens=input_tokens,
        completion_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )


def _map_error(error: BaseException, model: str) -> LLMError:
    if isinstance(error, LLMError):
        return error

    detail = _safe_detail(error)

    if isinstance(error, anthropic.AuthenticationError):
        return LLMAuthenticationError(
            "provider rejected the credentials",
            provider=PROVIDER_NAME,
            model=model,
            status_code=getattr(error, "status_code", 401),
        )
    if isinstance(error, anthropic.RateLimitError):
        return LLMRateLimitError(
            "provider is rate limiting the request",
            provider=PROVIDER_NAME,
            model=model,
            status_code=getattr(error, "status_code", 429),
        )
    if isinstance(error, anthropic.NotFoundError):
        return LLMModelUnavailableError(
            f"model {model!r} is unavailable or not accessible",
            provider=PROVIDER_NAME,
            model=model,
            status_code=getattr(error, "status_code", 404),
        )
    if isinstance(error, anthropic.InternalServerError):
        return LLMServiceUnavailableError(
            f"provider reported an internal error: {detail}",
            provider=PROVIDER_NAME,
            model=model,
            status_code=getattr(error, "status_code", 500),
        )
    if isinstance(error, anthropic.APITimeoutError):
        return LLMTimeoutError(
            "request timed out",
            provider=PROVIDER_NAME,
            model=model,
        )
    if isinstance(error, anthropic.APIConnectionError):
        return LLMConnectionError(
            f"could not reach the provider: {detail}",
            provider=PROVIDER_NAME,
            model=model,
        )
    if isinstance(error, anthropic.APIStatusError):
        code = getattr(error, "status_code", None)
        if code is not None and 500 <= code < 600:
            return LLMServiceUnavailableError(
                f"provider reported an internal error: {detail}",
                provider=PROVIDER_NAME,
                model=model,
                status_code=code,
            )
        return LLMProviderError(
            f"provider call failed ({type(error).__name__}): {detail}",
            provider=PROVIDER_NAME,
            model=model,
            status_code=code,
        )

    kind = type(error).__name__.lower()
    if isinstance(error, TimeoutError) or "timeout" in kind:
        return LLMTimeoutError(
            "request timed out",
            provider=PROVIDER_NAME,
            model=model,
        )
    if "connect" in kind or "network" in kind:
        return LLMConnectionError(
            f"could not reach the provider: {detail}",
            provider=PROVIDER_NAME,
            model=model,
        )
    return LLMProviderError(
        f"provider call failed ({type(error).__name__}): {detail}",
        provider=PROVIDER_NAME,
        model=model,
    )


def _safe_detail(error: BaseException) -> str:
    text = str(error).strip().replace("\n", " ")
    if len(text) <= _MAX_ERROR_DETAIL:
        return text or type(error).__name__
    return f"{text[:_MAX_ERROR_DETAIL]}..."
