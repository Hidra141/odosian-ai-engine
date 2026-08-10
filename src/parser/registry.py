"""Parser registry.

Holds the available format parsers and selects among them.

The registry knows nothing about any particular format. It is constructed with
whatever parsers a caller supplies, so adding a format means writing one class
that satisfies :class:`FormatParser` and registering it — no module here
changes.

It is immutable: :meth:`ParserRegistry.register` returns a new registry rather
than mutating a shared one, so no module-level state accumulates parsers over
the life of a process.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .base_parser import FormatParser
from .exceptions import UnsupportedRuleFormatError
from .types import RawDocument, RuleFormat


@dataclass(frozen=True, slots=True)
class ParserRegistry:
    """An ordered, immutable collection of format parsers."""

    parsers: tuple[FormatParser, ...] = ()

    @classmethod
    def of(cls, parsers: Iterable[FormatParser]) -> ParserRegistry:
        """Build a registry from an iterable of parsers, preserving order."""
        return cls(tuple(parsers))

    def register(self, parser: FormatParser) -> ParserRegistry:
        """Return a new registry with one parser appended."""
        return ParserRegistry((*self.parsers, parser))

    @property
    def formats(self) -> tuple[RuleFormat, ...]:
        """Return the formats this registry can parse, in selection order."""
        return tuple(parser.rule_format for parser in self.parsers)

    def detect(self, document: RawDocument) -> FormatParser:
        """Return the first parser that recognises the document.

        Order matters: the first match wins, so a registry places more specific
        parsers before more permissive ones.
        """
        for parser in self.parsers:
            if parser.can_parse(document):
                return parser
        raise UnsupportedRuleFormatError(self.formats)

    def for_format(self, rule_format: RuleFormat) -> FormatParser:
        """Return the parser handling a named format."""
        for parser in self.parsers:
            if parser.rule_format is rule_format:
                return parser
        raise UnsupportedRuleFormatError(self.formats)
