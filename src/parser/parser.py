"""Rule parsing entry point.

Decodes rule text into a document, selects a parser for it, and returns the
unified model.

Decoding is chosen by the document's first character rather than attempted
blindly: YAML would happily accept JSON, but a malformed JSON rule would then
be reported as a YAML error, which sends a reader looking in the wrong place.

Nothing here interprets a rule. Detection logic, entities and identifiers are
left exactly as the rule stated them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, final

import yaml

from .base_parser import FormatParser
from .elastic_parser import ElasticParser
from .exceptions import InvalidRuleFormatError
from .models import ParsedRule
from .registry import ParserRegistry
from .sigma_parser import SigmaParser
from .types import RawDocument, RuleFormat

_JSON_OPENERS: Final[str] = "{["


def default_registry() -> ParserRegistry:
    """Return a registry holding the parsers supported in the MVP.

    Sigma is tried first: its ``detection`` mapping is a precise discriminator,
    while the Elastic check is deliberately broader.
    """
    return ParserRegistry.of((SigmaParser(), ElasticParser()))


def decode_document(text: str) -> RawDocument:
    """Decode rule text into a document.

    JSON is used when the text opens with a JSON delimiter, YAML otherwise.
    """
    body = text.strip()
    if not body:
        raise InvalidRuleFormatError("input is empty")
    document = _decode_json(body) if body[0] in _JSON_OPENERS else _decode_yaml(body)
    if document is None:
        raise InvalidRuleFormatError("document is empty")
    if not isinstance(document, Mapping):
        raise InvalidRuleFormatError(
            f"expected a mapping at the top level, got {type(document).__name__}"
        )
    return {str(key): value for key, value in document.items()}


def _decode_json(body: str) -> object:
    """Decode a JSON document."""
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise InvalidRuleFormatError(f"invalid JSON: {error.msg} at position {error.pos}") from error


def _decode_yaml(body: str) -> object:
    """Decode a YAML document."""
    try:
        return yaml.safe_load(body)
    except yaml.YAMLError as error:
        raise InvalidRuleFormatError(f"invalid YAML: {error}") from error


@final
@dataclass(frozen=True, slots=True)
class RuleParser:
    """Parses detection rule text into the unified model."""

    registry: ParserRegistry = field(default_factory=default_registry)

    @property
    def supported_formats(self) -> tuple[RuleFormat, ...]:
        """Return the formats this parser can handle."""
        return self.registry.formats

    def parse(self, text: str) -> ParsedRule:
        """Decode, detect and parse a rule of any supported format."""
        document = decode_document(text)
        parser = self.registry.detect(document)
        return parser.parse(document, text)

    def parse_as(self, text: str, rule_format: RuleFormat) -> ParsedRule:
        """Parse a rule with a named format, skipping detection."""
        document = decode_document(text)
        parser = self.registry.for_format(rule_format)
        return parser.parse(document, text)

    def detect_format(self, text: str) -> RuleFormat:
        """Return the format a rule would be parsed as, without parsing it."""
        return self._select(decode_document(text)).rule_format

    def _select(self, document: RawDocument) -> FormatParser:
        """Return the parser that recognises a decoded document."""
        return self.registry.detect(document)
