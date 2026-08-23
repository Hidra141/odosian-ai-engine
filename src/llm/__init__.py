"""LLM provider.

Provider-agnostic abstraction over language model backends.

The layer executes prompts and nothing else. It receives a fully rendered
prompt, sends it to the configured provider, and returns a common response
object. It does not author, render or validate prompts, build context, retrieve
knowledge, or interpret what the model returned.

Typical use from the engine::

    provider = GeminiProvider(api_key=loaded.secrets["LLM_API_KEY"])
    client = LLMClient.create(provider, loaded.config.model)
    response = client.execute(rendered_prompt)

Parsing the response body is left to the caller, via :func:`parse_json_object`,
so this layer never decides what a well-formed result looks like.
"""

from __future__ import annotations

from .client import LLMClient
from .exceptions import (
    LLMAuthenticationError,
    LLMConnectionError,
    LLMError,
    LLMInvalidJSONError,
    LLMInvalidResponseError,
    LLMModelUnavailableError,
    LLMProviderError,
    LLMRateLimitError,
    LLMServiceUnavailableError,
    LLMTimeoutError,
)
from .anthropic_provider import AnthropicProvider
from .gemini_provider import PROVIDER_NAME, GeminiProvider
from .json_parser import parse_json, parse_json_object
from .openai_provider import OpenAICompatibleProvider
from .provider import LLMProvider
from .request import GenerationParameters, LLMRequest
from .response import LLMResponse, TokenUsage
from .retry import RetryExecutor, RetryObserver, RetryPolicy
from .types import (
    FinishReason,
    JSONObject,
    JSONSchema,
    JSONValue,
    ProviderMetadata,
    ResponseFormat,
)

__all__ = [
    "PROVIDER_NAME",
    "AnthropicProvider",
    "FinishReason",
    "GeminiProvider",
    "GenerationParameters",
    "JSONObject",
    "JSONSchema",
    "JSONValue",
    "LLMAuthenticationError",
    "LLMClient",
    "LLMConnectionError",
    "LLMError",
    "LLMInvalidJSONError",
    "LLMInvalidResponseError",
    "LLMModelUnavailableError",
    "LLMProvider",
    "LLMProviderError",
    "OpenAICompatibleProvider",
    "LLMRateLimitError",
    "LLMRequest",
    "LLMResponse",
    "LLMServiceUnavailableError",
    "LLMTimeoutError",
    "ProviderMetadata",
    "ResponseFormat",
    "RetryExecutor",
    "RetryObserver",
    "RetryPolicy",
    "TokenUsage",
]
