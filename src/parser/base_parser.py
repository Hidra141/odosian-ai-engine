"""Format parser contract.

Defines the interface a format parser satisfies, and the field-reading helpers
every parser shares.

The helpers exist so that reading a field is uniform across formats: a value of
the wrong type raises :class:`ParseFailureError` naming the field, rather than
propagating as a confusing failure later. They read; they never coerce a value
into a different shape or supply one the rule did not state.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from .exceptions import ParseFailureError
from .models import ParsedRule
from .types import RawDocument, RuleFormat, RuleValue


@runtime_checkable
class FormatParser(Protocol):
    """Parses one detection rule format into the unified model."""

    @property
    def rule_format(self) -> RuleFormat:
        """Return the format this parser handles."""
        ...

    def can_parse(self, document: RawDocument) -> bool:
        """Return whether this parser recognises the document's shape.

        Recognition inspects structure only. It must not raise, so detection can
        try every registered parser in turn.
        """
        ...

    def parse(self, document: RawDocument, source_text: str) -> ParsedRule:
        """Build a parsed rule from a document this parser recognises."""
        ...


def require_str(
    document: RawDocument,
    key: str,
    *,
    rule_format: RuleFormat,
) -> str:
    """Return a string field that the format requires."""
    value = document.get(key)
    if value is None:
        raise ParseFailureError(rule_format, "required field is missing", field=key)
    if not isinstance(value, str) or not value.strip():
        raise ParseFailureError(rule_format, "expected a non-empty string", field=key)
    return value


def require_mapping(
    document: RawDocument,
    key: str,
    *,
    rule_format: RuleFormat,
) -> Mapping[str, RuleValue]:
    """Return a mapping field that the format requires."""
    value = document.get(key)
    if value is None:
        raise ParseFailureError(rule_format, "required section is missing", field=key)
    if not isinstance(value, Mapping):
        raise ParseFailureError(rule_format, "expected a mapping", field=key)
    return value


def optional_str(document: RawDocument, key: str) -> str | None:
    """Return a string field, or ``None`` when unset or not a scalar."""
    value = document.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def optional_int(document: RawDocument, key: str) -> int | None:
    """Return an integer field, or ``None`` when unset or not an integer."""
    value = document.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def optional_mapping(document: RawDocument, key: str) -> Mapping[str, RuleValue] | None:
    """Return a mapping field, or ``None`` when unset or not a mapping."""
    value = document.get(key)
    if isinstance(value, Mapping):
        return value
    return None


def string_tuple(document: RawDocument, key: str) -> tuple[str, ...]:
    """Return a field as a tuple of strings.

    Accepts a single string or a sequence of them, because formats differ on
    whether a one-element field is written as a scalar. Non-string members are
    skipped rather than stringified, so nothing is invented.
    """
    value = document.get(key)
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, Sequence):
        return tuple(item for item in value if isinstance(item, str) and item.strip())
    return ()
