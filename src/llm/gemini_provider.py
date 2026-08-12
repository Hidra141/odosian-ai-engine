"""Google Gemini adapter.

The only module in the engine that imports the Gemini SDK. It translates an
:class:`LLMRequest` into an SDK call, the SDK result into an
:class:`LLMResponse`, and every SDK exception into this package's hierarchy.

The API key arrives as a :class:`Secret` and is revealed once, when the SDK
client is constructed. It is never stored in plain form, never placed in an
exception message, and never logged.
"""

from __future__ import annotations

import time
from typing import Any, Final, Protocol, final

from google import genai
from google.genai import types as genai_types

from src.config.secrets import Secret
from src.config.types import ThinkingLevel

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

PROVIDER_NAME: Final[str] = "gemini"

_JSON_MIME_TYPE: Final[str] = "application/json"
_TEXT_MIME_TYPE: Final[str] = "text/plain"
_MILLISECONDS_PER_SECOND: Final[int] = 1000
_MAX_ERROR_DETAIL: Final[int] = 200

_THINKING_LEVELS: Final[dict[ThinkingLevel, genai_types.ThinkingLevel]] = {
    ThinkingLevel.MINIMAL: genai_types.ThinkingLevel.MINIMAL,
    ThinkingLevel.LOW: genai_types.ThinkingLevel.LOW,
    ThinkingLevel.MEDIUM: genai_types.ThinkingLevel.MEDIUM,
    ThinkingLevel.HIGH: genai_types.ThinkingLevel.HIGH,
}
"""The engine's neutral levels mapped onto Gemini's own vocabulary.

Written as a table rather than upper-casing the value, so a level this adapter
has not been taught fails at the mapping instead of reaching the API as a
plausible-looking string.
"""

_AUTH_CODES: Final[frozenset[int]] = frozenset({401, 403})
_NOT_FOUND_CODES: Final[frozenset[int]] = frozenset({404})
_RATE_LIMIT_CODES: Final[frozenset[int]] = frozenset({429})


class GeminiModels(Protocol):
    """The subset of the SDK's model interface this adapter calls."""

    def generate_content(self, *, model: str, contents: str, config: Any) -> Any:
        """Execute one generation call."""
        ...


class GeminiClient(Protocol):
    """The subset of the SDK client this adapter uses."""

    @property
    def models(self) -> GeminiModels:
        """Return the model interface."""
        ...


@final
class GeminiProvider:
    """Executes requests against Google Gemini."""

    __slots__ = ("_client",)

    def __init__(self, api_key: Secret, client: GeminiClient | None = None) -> None:
        """Build the adapter, constructing an SDK client unless one is supplied.

        Injecting a client keeps the adapter testable without a network or a
        credential.
        """
        self._client: GeminiClient = (
            client if client is not None else genai.Client(api_key=api_key.reveal())
        )

    @property
    def name(self) -> str:
        """Return this provider's identifier."""
        return PROVIDER_NAME

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Execute one request and return the response."""
        config = self._build_config(request)
        started = time.perf_counter()
        try:
            raw = self._client.models.generate_content(
                model=request.parameters.model,
                contents=request.instruction,
                config=config,
            )
        except BaseException as error:  # noqa: BLE001 - SDK errors must not escape
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise _map_error(error, request) from error
        duration = time.perf_counter() - started
        return _build_response(raw, request, duration)

    def _build_config(self, request: LLMRequest) -> Any:
        """Translate the request's parameters into an SDK configuration object."""
        parameters = request.parameters
        mime_type = (
            _JSON_MIME_TYPE
            if request.response_format is ResponseFormat.JSON
            else _TEXT_MIME_TYPE
        )
        schema = request.response_json_schema if mime_type == _JSON_MIME_TYPE else None
        return genai_types.GenerateContentConfig(
            system_instruction=request.system if request.has_system else None,
            temperature=parameters.temperature,
            top_p=parameters.top_p,
            max_output_tokens=parameters.max_output_tokens,
            response_mime_type=mime_type,
            response_json_schema=dict(schema) if schema is not None else None,
            thinking_config=_thinking_config(parameters.thinking_level),
            http_options=genai_types.HttpOptions(
                timeout=parameters.timeout_seconds * _MILLISECONDS_PER_SECOND,
            ),
        )


def _thinking_config(level: ThinkingLevel | None) -> Any:
    """Translate the neutral thinking level into the SDK's own configuration.

    ``None`` yields no configuration at all, leaving the provider's default
    behaviour untouched — which is what every call did before this setting
    existed.

    Only ``thinking_level`` is ever set. The SDK also accepts a
    ``thinking_budget`` expressed in tokens, and will serialise both together
    without complaint, but the two are alternative ways of saying the same
    thing and sending both leaves the model to decide which one it honours.
    """
    if level is None:
        return None
    return genai_types.ThinkingConfig(thinking_level=_THINKING_LEVELS[level])


def _build_response(raw: Any, request: LLMRequest, duration: float) -> LLMResponse:
    """Translate an SDK result into the common response object."""
    model = request.parameters.model
    finish_reason = _extract_finish_reason(raw)
    text = _extract_text(raw)
    if not text and finish_reason is FinishReason.UNKNOWN:
        raise LLMInvalidResponseError(
            "provider returned no text and no finish reason",
            provider=PROVIDER_NAME,
            model=model,
        )
    return LLMResponse(
        text=text,
        provider=PROVIDER_NAME,
        model=model,
        finish_reason=finish_reason,
        usage=_extract_usage(raw),
        duration_seconds=duration,
    )


def _extract_text(raw: Any) -> str:
    """Return the generated text, or an empty string when none was produced."""
    value = getattr(raw, "text", None)
    return value if isinstance(value, str) else ""


def _extract_finish_reason(raw: Any) -> FinishReason:
    """Return the finish reason of the first candidate."""
    candidates = getattr(raw, "candidates", None)
    if not candidates:
        return FinishReason.UNKNOWN
    reason = getattr(candidates[0], "finish_reason", None)
    if reason is None:
        return FinishReason.UNKNOWN
    token = getattr(reason, "name", None)
    return FinishReason.from_provider(token if isinstance(token, str) else str(reason))


def _extract_usage(raw: Any) -> TokenUsage:
    """Return the reported token usage, zeroed when the provider reports none."""
    metadata = getattr(raw, "usage_metadata", None)
    if metadata is None:
        return TokenUsage.unknown()
    return TokenUsage(
        prompt_tokens=_as_int(getattr(metadata, "prompt_token_count", 0)),
        completion_tokens=_as_int(getattr(metadata, "candidates_token_count", 0)),
        total_tokens=_as_int(getattr(metadata, "total_token_count", 0)),
        thoughts_tokens=_as_int(getattr(metadata, "thoughts_token_count", 0)),
    )


def _as_int(value: Any) -> int:
    """Return an integer token count, defaulting to zero."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _map_error(error: BaseException, request: LLMRequest) -> LLMError:
    """Translate an SDK or transport exception into this package's hierarchy."""
    if isinstance(error, LLMError):
        return error

    model = request.parameters.model
    detail = _safe_detail(error)
    kind = type(error).__name__.lower()

    if isinstance(error, TimeoutError) or "timeout" in kind:
        return LLMTimeoutError(
            f"request timed out after {request.parameters.timeout_seconds}s",
            provider=PROVIDER_NAME,
            model=model,
        )

    code = _status_code(error)
    if code in _AUTH_CODES:
        return LLMAuthenticationError(
            "provider rejected the credentials",
            provider=PROVIDER_NAME,
            model=model,
            status_code=code,
        )
    if code in _RATE_LIMIT_CODES:
        return LLMRateLimitError(
            "provider is rate limiting the request",
            provider=PROVIDER_NAME,
            model=model,
            status_code=code,
        )
    if code in _NOT_FOUND_CODES:
        return LLMModelUnavailableError(
            f"model {model!r} is unavailable or not accessible",
            provider=PROVIDER_NAME,
            model=model,
            status_code=code,
        )
    if code is not None and 500 <= code < 600:
        return LLMServiceUnavailableError(
            f"provider reported an internal error: {detail}",
            provider=PROVIDER_NAME,
            model=model,
            status_code=code,
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
        status_code=code,
    )


def _status_code(error: BaseException) -> int | None:
    """Return the HTTP status code an SDK exception carries, when it carries one."""
    for attribute in ("code", "status_code"):
        value = getattr(error, attribute, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    response = getattr(error, "response", None)
    if response is not None:
        value = getattr(response, "status_code", None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _safe_detail(error: BaseException) -> str:
    """Return a bounded description of a failure, suitable to surface."""
    text = str(error).strip().replace("\n", " ")
    if len(text) <= _MAX_ERROR_DETAIL:
        return text or type(error).__name__
    return f"{text[:_MAX_ERROR_DETAIL]}..."
