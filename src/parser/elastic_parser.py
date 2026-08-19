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

``threat`` is not one of those. Elastic states its ATT&CK references there and
nowhere else — its ``tags`` are editorial labels like ``Elastic`` and ``Host``,
and across the bundled corpus not one of 2,145 rules writes an ATT&CK
identifier among them. Sigma writes them as tags, so every stage after this one
learned to look there, and an Elastic rule's techniques reached nothing. They
are read here, into the field that says what they are.

Only the identifiers are read. Their tactics are deliberately left for a
separate decision, and nothing here judges whether an identifier is well-formed
or real: this parser reports what the rule states, and Stage-10 owns identifier
syntax.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final, final

from .base_parser import optional_int, optional_str, require_str, string_tuple
from .models import AttackReference, Condition, Detection, LogSource, ParsedRule, RuleMetadata
from .types import RawDocument, RuleFormat, RuleLanguage, RuleSeverity, RuleStatus

_NAME_KEY: Final[str] = "name"
_IDENTIFIER_KEYS: Final[tuple[str, ...]] = ("rule_id", "id")
_THREAT_KEY: Final[str] = "threat"
_TECHNIQUE_KEY: Final[str] = "technique"
_SUBTECHNIQUE_KEY: Final[str] = "subtechnique"


def _members(value: object) -> Sequence[object]:
    """Return a value's members when it is a list of things, and none otherwise.

    Strings and bytes are sequences and are excluded, because a ``threat``
    written as a string is a malformed rule rather than a list of its
    characters. Everything else that is not a sequence contributes nothing,
    which is how a null, a number or a mapping in a list position is handled
    without a test for each.
    """
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return value
    return ()


def _record(found: dict[str, AttackReference], value: object, location: str) -> None:
    """Keep one stated identifier, the first time the rule states it."""
    if isinstance(value, str) and value.strip():
        found.setdefault(value.strip(), AttackReference(value.strip(), location))


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
            attack_references=self._attack_references(document),
        )

    def _attack_references(self, document: RawDocument) -> tuple[AttackReference, ...]:
        """Read the ATT&CK identifiers the rule's threat section states.

        A technique and each of its sub-techniques are both reported, because a
        rule naming ``T1059`` with a ``T1059.001`` beneath it is stating both
        and either may be the one a corpus answers to.

        Repeats are dropped. Elastic states one threat entry per tactic, so a
        technique serving two tactics is written twice — 492 of the bundled
        2,145 rules do exactly that — and reporting it twice would give a later
        stage two entities for one statement. The first occurrence wins, so the
        order is the order the rule reads in.

        Nothing raises. A ``threat`` that is absent, null, a string or a list of
        numbers states no identifier, and so does a technique with no ``id`` or
        an ``id`` that is not a string. Each of those is a rule that said
        nothing here, not a rule that failed to parse.
        """
        found: dict[str, AttackReference] = {}
        for entry_index, entry in enumerate(_members(document.get(_THREAT_KEY))):
            if not isinstance(entry, Mapping):
                continue
            for index, technique in enumerate(_members(entry.get(_TECHNIQUE_KEY))):
                if not isinstance(technique, Mapping):
                    continue
                location = f"{_THREAT_KEY}[{entry_index}].{_TECHNIQUE_KEY}[{index}]"
                _record(found, technique.get("id"), location)
                for sub_index, sub in enumerate(_members(technique.get(_SUBTECHNIQUE_KEY))):
                    if not isinstance(sub, Mapping):
                        continue
                    _record(
                        found,
                        sub.get("id"),
                        f"{location}.{_SUBTECHNIQUE_KEY}[{sub_index}]",
                    )
        return tuple(found.values())

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
