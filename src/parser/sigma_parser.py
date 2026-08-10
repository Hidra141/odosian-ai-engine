"""Sigma parser.

Parses Sigma rules, which are YAML documents carrying a ``logsource`` taxonomy
and a ``detection`` block of named search identifiers plus a ``condition``.

The search identifiers are copied across untouched. Their field modifiers
(``|endswith``, ``|contains|all``) are Sigma's own matching semantics, and
resolving them is detection logic rather than structure.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final, final

from .base_parser import (
    optional_mapping,
    optional_str,
    require_mapping,
    require_str,
    string_tuple,
)
from .exceptions import ParseFailureError
from .models import Condition, Detection, LogSource, ParsedRule, RuleMetadata
from .types import (
    RawDocument,
    RuleFormat,
    RuleLanguage,
    RuleSeverity,
    RuleStatus,
    RuleValue,
)

_CONDITION_KEY: Final[str] = "condition"
_TIMEFRAME_KEY: Final[str] = "timeframe"
_DETECTION_KEY: Final[str] = "detection"
_RESERVED_DETECTION_KEYS: Final[frozenset[str]] = frozenset({_CONDITION_KEY, _TIMEFRAME_KEY})


@final
class SigmaParser:
    """Parses Sigma YAML rules into the unified model."""

    __slots__ = ()

    @property
    def rule_format(self) -> RuleFormat:
        """Return the format this parser handles."""
        return RuleFormat.SIGMA

    def can_parse(self, document: RawDocument) -> bool:
        """Return whether the document looks like a Sigma rule.

        A ``detection`` mapping is the discriminator: it is mandatory in Sigma
        and absent from Elastic rules.
        """
        return isinstance(document.get(_DETECTION_KEY), Mapping)

    def parse(self, document: RawDocument, source_text: str) -> ParsedRule:
        """Build a parsed rule from a Sigma document."""
        detection_block = require_mapping(document, _DETECTION_KEY, rule_format=RuleFormat.SIGMA)
        return ParsedRule(
            rule_format=RuleFormat.SIGMA,
            metadata=self._metadata(document),
            log_source=self._log_source(document),
            detection=self._detection(detection_block),
            condition=self._condition(detection_block),
            tags=string_tuple(document, "tags"),
            references=string_tuple(document, "references"),
            false_positives=string_tuple(document, "falsepositives"),
            raw=document,
            source_text=source_text,
        )

    def _metadata(self, document: RawDocument) -> RuleMetadata:
        """Read the rule's descriptive fields."""
        return RuleMetadata(
            title=require_str(document, "title", rule_format=RuleFormat.SIGMA),
            identifier=optional_str(document, "id"),
            description=optional_str(document, "description"),
            authors=string_tuple(document, "author"),
            status=RuleStatus.from_value(optional_str(document, "status")),
            severity=RuleSeverity.from_value(optional_str(document, "level")),
            version=optional_str(document, "version"),
            created=optional_str(document, "date"),
            modified=optional_str(document, "modified"),
        )

    def _log_source(self, document: RawDocument) -> LogSource:
        """Read the ``logsource`` taxonomy."""
        section = optional_mapping(document, "logsource")
        if section is None:
            return LogSource()
        return LogSource(
            category=optional_str(section, "category"),
            product=optional_str(section, "product"),
            service=optional_str(section, "service"),
            definition=optional_str(section, "definition"),
        )

    def _detection(self, detection_block: Mapping[str, RuleValue]) -> Detection:
        """Read the search identifiers, excluding the condition and timeframe."""
        definitions = {
            name: value
            for name, value in detection_block.items()
            if name not in _RESERVED_DETECTION_KEYS
        }
        return Detection(
            definitions=definitions,
            language=RuleLanguage.SIGMA,
        )

    def _condition(self, detection_block: Mapping[str, RuleValue]) -> Condition:
        """Read the condition expressions and the optional timeframe."""
        raw_condition = detection_block.get(_CONDITION_KEY)
        if raw_condition is None:
            raise ParseFailureError(
                RuleFormat.SIGMA,
                "required field is missing",
                field=f"{_DETECTION_KEY}.{_CONDITION_KEY}",
            )
        expressions = _condition_expressions(raw_condition)
        if not expressions:
            raise ParseFailureError(
                RuleFormat.SIGMA,
                "expected a string or a sequence of strings",
                field=f"{_DETECTION_KEY}.{_CONDITION_KEY}",
            )
        timeframe = detection_block.get(_TIMEFRAME_KEY)
        return Condition(
            expressions=expressions,
            timeframe=timeframe if isinstance(timeframe, str) else None,
        )


def _condition_expressions(value: RuleValue) -> tuple[str, ...]:
    """Return the condition as a tuple, accepting Sigma's scalar or list form."""
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, Sequence):
        return tuple(item for item in value if isinstance(item, str) and item.strip())
    return ()
