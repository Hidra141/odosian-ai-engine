"""LLM layer types.

Provider-neutral type definitions. Nothing here refers to a specific provider
SDK, so the rest of the engine can depend on these names without depending on
how any particular provider represents them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum

type JSONValue = str | int | float | bool | None | Sequence[JSONValue] | Mapping[str, JSONValue]
type JSONObject = Mapping[str, JSONValue]
type ProviderMetadata = Mapping[str, str]

type JSONSchema = Mapping[str, JSONValue]
"""A JSON Schema document, as plain JSON.

Deliberately a mapping rather than a provider's schema class. A caller states
the shape it expects in the vendor-neutral language of JSON Schema, and each
adapter translates that into whatever its own SDK wants. Nothing outside an
adapter ever holds a provider's schema type.
"""


class FinishReason(StrEnum):
    """Why the provider stopped generating."""

    STOP = "stop"
    MAX_TOKENS = "max_tokens"
    SAFETY = "safety"
    RECITATION = "recitation"
    ERROR = "error"
    UNKNOWN = "unknown"

    @classmethod
    def from_provider(cls, value: str | None) -> FinishReason:
        """Map a provider's finish reason onto the neutral vocabulary."""
        if value is None:
            return cls.UNKNOWN
        token = value.strip().upper()
        mapping = {
            "STOP": cls.STOP,
            "END_TURN": cls.STOP,
            "COMPLETE": cls.STOP,
            "MAX_TOKENS": cls.MAX_TOKENS,
            "LENGTH": cls.MAX_TOKENS,
            "SAFETY": cls.SAFETY,
            "BLOCKLIST": cls.SAFETY,
            "PROHIBITED_CONTENT": cls.SAFETY,
            "RECITATION": cls.RECITATION,
            "ERROR": cls.ERROR,
            "MALFORMED_FUNCTION_CALL": cls.ERROR,
        }
        return mapping.get(token, cls.UNKNOWN)


class ResponseFormat(StrEnum):
    """The response format asked of the provider."""

    JSON = "json"
    TEXT = "text"
