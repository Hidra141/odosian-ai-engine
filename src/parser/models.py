"""Rule parser models.

The unified representation every supported format is parsed into.

These models describe a rule's *structure*. They record what the rule says, not
what it means: no field here holds an entity, a resolved identifier, or a
judgement about the detection logic. A section a format does not have stays
empty rather than being filled by inference.

The original rule survives parsing twice over — as the decoded document in
:attr:`ParsedRule.raw` and as the untouched input in
:attr:`ParsedRule.source_text` — so nothing downstream is forced to work from
this model alone.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .types import RawDocument, RuleFormat, RuleLanguage, RuleSeverity, RuleStatus, RuleValue


def _empty_document() -> RawDocument:
    """Return an immutable, empty document."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Who wrote the rule, what it claims to do, and how mature it is."""

    title: str
    identifier: str | None = None
    description: str | None = None
    authors: tuple[str, ...] = ()
    status: RuleStatus = RuleStatus.UNKNOWN
    severity: RuleSeverity = RuleSeverity.UNKNOWN
    risk_score: int | None = None
    version: str | None = None
    created: str | None = None
    modified: str | None = None

    @property
    def author(self) -> str | None:
        """Return the first declared author, if any."""
        return self.authors[0] if self.authors else None


@dataclass(frozen=True, slots=True)
class LogSource:
    """Where the rule expects its events to come from.

    Sigma describes this taxonomically (category, product, service); Elastic
    describes it by index pattern. Both shapes are held here, and a format
    populates only the fields it actually declares.
    """

    category: str | None = None
    product: str | None = None
    service: str | None = None
    definition: str | None = None
    indices: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Return whether the rule declared no log source at all."""
        return not any((self.category, self.product, self.service, self.definition, self.indices))


@dataclass(frozen=True, slots=True)
class Detection:
    """The rule's detection body, preserved without interpretation.

    ``definitions`` carries a format's named search blocks — Sigma's search
    identifiers. ``query`` carries a single query expression, as Elastic uses.
    A format populates whichever it has; neither is translated into the other.
    """

    definitions: Mapping[str, RuleValue] = field(default_factory=_empty_document)
    query: str | None = None
    language: RuleLanguage = RuleLanguage.UNKNOWN
    rule_type: str | None = None

    @property
    def is_empty(self) -> bool:
        """Return whether the rule declared no detection body."""
        return not self.definitions and not self.query


@dataclass(frozen=True, slots=True)
class Condition:
    """How the detection body is combined, as the rule states it.

    Sigma states this explicitly and may state several. Elastic has no separate
    condition — its query is its condition — so this section stays empty for
    Elastic rules rather than being synthesised from the query.
    """

    expressions: tuple[str, ...] = ()
    timeframe: str | None = None

    @property
    def expression(self) -> str | None:
        """Return the first condition expression, if any."""
        return self.expressions[0] if self.expressions else None

    @property
    def is_empty(self) -> bool:
        """Return whether the rule declared no condition."""
        return not self.expressions


@dataclass(frozen=True, slots=True)
class ParsedRule:
    """One detection rule, in unified structural form."""

    rule_format: RuleFormat
    metadata: RuleMetadata
    log_source: LogSource = field(default_factory=LogSource)
    detection: Detection = field(default_factory=Detection)
    condition: Condition = field(default_factory=Condition)
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    raw: RawDocument = field(default_factory=_empty_document, repr=False)
    source_text: str = field(default="", repr=False)

    @property
    def title(self) -> str:
        """Return the rule's title."""
        return self.metadata.title
