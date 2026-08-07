"""Rule parser.

Parsing of detection rules into a structured internal representation.

The package converts Sigma YAML and Elastic Security JSON rules into one
:class:`ParsedRule` model. It parses structure and nothing else: it does not
extract entities, resolve identifiers, interpret detection logic, retrieve
knowledge, or judge whether a rule is any good.

Typical use::

    parser = RuleParser()
    rule = parser.parse(rule_text)

Adding a format means writing one class satisfying :class:`FormatParser` and
registering it::

    parser = RuleParser(registry=default_registry().register(MyParser()))
"""

from __future__ import annotations

from .base_parser import FormatParser
from .elastic_parser import ElasticParser
from .exceptions import (
    InvalidRuleFormatError,
    ParseFailureError,
    ParserError,
    UnsupportedRuleFormatError,
)
from .models import Condition, Detection, LogSource, ParsedRule, RuleMetadata
from .parser import RuleParser, decode_document, default_registry
from .registry import ParserRegistry
from .sigma_parser import SigmaParser
from .types import (
    RawDocument,
    RuleFormat,
    RuleLanguage,
    RuleSeverity,
    RuleStatus,
    RuleValue,
)

__all__ = [
    "Condition",
    "Detection",
    "ElasticParser",
    "FormatParser",
    "InvalidRuleFormatError",
    "LogSource",
    "ParseFailureError",
    "ParsedRule",
    "ParserError",
    "ParserRegistry",
    "RawDocument",
    "RuleFormat",
    "RuleLanguage",
    "RuleMetadata",
    "RuleParser",
    "RuleSeverity",
    "RuleStatus",
    "RuleValue",
    "SigmaParser",
    "UnsupportedRuleFormatError",
    "decode_document",
    "default_registry",
]
