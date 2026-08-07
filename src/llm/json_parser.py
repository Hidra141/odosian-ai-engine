"""JSON parsing.

Parses a response body into JSON, or fails with a typed exception.

The parser is deliberately strict. It does not strip code fences, close
unbalanced brackets, remove trailing commas, or extract the first object it can
find in surrounding prose. A body that does not parse is reported as invalid and
left untouched, so the fault stays visible instead of being papered over.

The only transformation applied is stripping surrounding whitespace.

Structural checks stop at the JSON type. Whether the parsed document carries the
fields the engine expects is a question for the validation layer.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

from .exceptions import LLMInvalidJSONError, LLMInvalidResponseError
from .types import JSONObject, JSONValue


def parse_json(text: str, *, provider: str = "", model: str = "") -> JSONValue:
    """Parse a response body into a JSON value."""
    body = text.strip()
    if not body:
        raise LLMInvalidResponseError(
            "provider returned an empty response body",
            provider=provider,
            model=model,
        )
    try:
        return cast(JSONValue, json.loads(body))
    except json.JSONDecodeError as error:
        raise LLMInvalidJSONError(
            f"response body is not valid JSON: {error.msg} at position {error.pos}",
            provider=provider,
            model=model,
            position=error.pos,
        ) from error


def parse_json_object(text: str, *, provider: str = "", model: str = "") -> JSONObject:
    """Parse a response body that is required to be a JSON object."""
    value = parse_json(text, provider=provider, model=model)
    if not isinstance(value, Mapping):
        raise LLMInvalidResponseError(
            f"expected a JSON object, got {type(value).__name__}",
            provider=provider,
            model=model,
        )
    return cast(JSONObject, value)
