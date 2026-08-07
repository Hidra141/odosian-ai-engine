"""Rule parser types.

Format-neutral vocabulary shared by every parser.

Each enum carries an ``UNKNOWN`` member and a ``from_value`` mapper. A value a
format uses but this vocabulary does not recognise becomes ``UNKNOWN`` rather
than raising: an unfamiliar severity label is not a reason to reject a rule that
is otherwise well formed, and the original value survives in the preserved raw
document.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum

type RuleValue = str | int | float | bool | None | Sequence[RuleValue] | Mapping[str, RuleValue]
type RawDocument = Mapping[str, RuleValue]


class RuleFormat(StrEnum):
    """A detection rule format this package can parse."""

    SIGMA = "sigma"
    ELASTIC = "elastic"
    UNKNOWN = "unknown"


class RuleLanguage(StrEnum):
    """The query language a rule's detection is written in."""

    SIGMA = "sigma"
    KUERY = "kuery"
    EQL = "eql"
    LUCENE = "lucene"
    ESQL = "esql"
    UNKNOWN = "unknown"

    @classmethod
    def from_value(cls, value: str | None) -> RuleLanguage:
        """Map a format's language label onto the neutral vocabulary."""
        if value is None:
            return cls.UNKNOWN
        aliases: Mapping[str, RuleLanguage] = {
            "sigma": cls.SIGMA,
            "kuery": cls.KUERY,
            "kql": cls.KUERY,
            "eql": cls.EQL,
            "lucene": cls.LUCENE,
            "esql": cls.ESQL,
            "es|ql": cls.ESQL,
        }
        return aliases.get(value.strip().lower(), cls.UNKNOWN)


class RuleSeverity(StrEnum):
    """How severe a rule considers the behaviour it detects."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    @classmethod
    def from_value(cls, value: str | None) -> RuleSeverity:
        """Map a format's severity or level label onto the neutral vocabulary."""
        if value is None:
            return cls.UNKNOWN
        aliases: Mapping[str, RuleSeverity] = {
            "informational": cls.INFORMATIONAL,
            "info": cls.INFORMATIONAL,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return aliases.get(value.strip().lower(), cls.UNKNOWN)


class RuleStatus(StrEnum):
    """The maturity a rule declares for itself."""

    EXPERIMENTAL = "experimental"
    TEST = "test"
    STABLE = "stable"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"

    @classmethod
    def from_value(cls, value: str | None) -> RuleStatus:
        """Map a format's status label onto the neutral vocabulary."""
        if value is None:
            return cls.UNKNOWN
        aliases: Mapping[str, RuleStatus] = {
            "experimental": cls.EXPERIMENTAL,
            "test": cls.TEST,
            "testing": cls.TEST,
            "stable": cls.STABLE,
            "deprecated": cls.DEPRECATED,
            "unsupported": cls.UNSUPPORTED,
        }
        return aliases.get(value.strip().lower(), cls.UNKNOWN)
