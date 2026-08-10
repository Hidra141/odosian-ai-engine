"""Elastic parser.

Parses Elastic Security detection rules, which are JSON documents carrying a
single ``query`` in a named language, evaluated against index patterns.

Elastic has no condition section: its query is its condition. That section is
therefore left empty rather than synthesised from the query, because deriving
one would mean reading the detection logic.

Fields specific to a rule type — ``threshold``, ``new_terms_fields``,
``machine_learning_job_id`` and the like — are not lifted into the model. They
remain available in the preserved raw document, where their meaning stays tied
to the rule type that defines them.
"""

from __future__ import annotations

from typing import Final, final

from .base_parser import optional_int, optional_str, require_str, string_tuple
from .models import Condition, Detection, LogSource, ParsedRule, RuleMetadata
from .types import RawDocument, RuleFormat, RuleLanguage, RuleSeverity, RuleStatus

_NAME_KEY: Final[str] = "name"
_IDENTIFIER_KEYS: Final[tuple[str, ...]] = ("rule_id", "id")


@final
class ElasticParser:
    """Parses Elastic Security JSON rules into the unified model."""

    __slots__ = ()

    @property
    def rule_format(self) -> RuleFormat:
        """Return the format this parser handles."""
        return RuleFormat.ELASTIC

    def can_parse(self, document: RawDocument) -> bool:
        """Return whether the document looks like an Elastic detection rule.

        Requires a name or rule identifier together with a query or a rule type.
        Either signal alone is too weak: many documents carry a name.
        """
        named = _NAME_KEY in document or any(key in document for key in _IDENTIFIER_KEYS)
        detects = "query" in document or "type" in document
        return named and detects

    def parse(self, document: RawDocument, source_text: str) -> ParsedRule:
        """Build a parsed rule from an Elastic document."""
        return ParsedRule(
            rule_format=RuleFormat.ELASTIC,
            metadata=self._metadata(document),
            log_source=self._log_source(document),
            detection=self._detection(document),
            condition=Condition(),
            tags=string_tuple(document, "tags"),
            references=string_tuple(document, "references"),
            false_positives=string_tuple(document, "false_positives"),
            raw=document,
            source_text=source_text,
        )

    def _metadata(self, document: RawDocument) -> RuleMetadata:
        """Read the rule's descriptive fields."""
        return RuleMetadata(
            title=require_str(document, _NAME_KEY, rule_format=RuleFormat.ELASTIC),
            identifier=self._identifier(document),
            description=optional_str(document, "description"),
            authors=string_tuple(document, "author"),
            status=RuleStatus.UNKNOWN,
            severity=RuleSeverity.from_value(optional_str(document, "severity")),
            risk_score=optional_int(document, "risk_score"),
            version=optional_str(document, "version"),
            created=optional_str(document, "created_at"),
            modified=optional_str(document, "updated_at"),
        )

    def _identifier(self, document: RawDocument) -> str | None:
        """Return the first identifier the rule declares."""
        for key in _IDENTIFIER_KEYS:
            value = optional_str(document, key)
            if value is not None:
                return value
        return None

    def _log_source(self, document: RawDocument) -> LogSource:
        """Read the index patterns the rule runs against."""
        return LogSource(indices=string_tuple(document, "index"))

    def _detection(self, document: RawDocument) -> Detection:
        """Read the query, its language and the rule type."""
        return Detection(
            query=optional_str(document, "query"),
            language=RuleLanguage.from_value(optional_str(document, "language")),
            rule_type=optional_str(document, "type"),
        )
