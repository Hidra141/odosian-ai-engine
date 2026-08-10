"""Rule parser exceptions.

Every failure leaving this package is one of these types.

The hierarchy separates three distinct failures that are easy to confuse:

- the text is not a document at all (:class:`InvalidRuleFormatError`)
- it is a document, but no parser recognises it (:class:`UnsupportedRuleFormatError`)
- a parser recognised it, but its structure is not usable (:class:`ParseFailureError`)

A caller that cannot tell these apart cannot tell a corrupt file from an
unsupported vendor.
"""

from __future__ import annotations

from collections.abc import Sequence

from .types import RuleFormat


class ParserError(Exception):
    """Base class for every rule parsing failure."""


class InvalidRuleFormatError(ParserError):
    """The input is not a decodable document, or is not a mapping."""

    def __init__(self, reason: str) -> None:
        """Record why the input could not be decoded."""
        super().__init__(f"Rule could not be decoded: {reason}")
        self.reason = reason


class UnsupportedRuleFormatError(ParserError):
    """No registered parser recognises the document."""

    def __init__(self, supported: Sequence[RuleFormat]) -> None:
        """Record the formats that were available when detection failed."""
        names = ", ".join(item.value for item in supported) or "none"
        super().__init__(f"No parser recognised the rule; registered formats: {names}")
        self.supported = tuple(supported)


class ParseFailureError(ParserError):
    """A parser recognised the document but could not build a rule from it."""

    def __init__(self, rule_format: RuleFormat, reason: str, *, field: str | None = None) -> None:
        """Record the format, the offending field and why parsing stopped."""
        location = f" at {field!r}" if field else ""
        super().__init__(f"Failed to parse {rule_format.value} rule{location}: {reason}")
        self.rule_format = rule_format
        self.reason = reason
        self.field = field
