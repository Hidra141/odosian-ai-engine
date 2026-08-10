"""Entity extraction models.

The entities produced by this stage, and the collection returned to the caller.

An :class:`Entity` is a value plus its provenance. It carries no meaning: there
is no canonical form, no resolved identifier, no severity judgement and no
technique. Every value appears exactly as it was written in the rule.

The collection is a list, not a set. Requirements forbid deduplication and
merging, so a value found by two routes appears twice, each occurrence carrying
the extractor and location that produced it. Grouping helpers return views over
that list; none of them collapse anything.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from src.parser.models import ParsedRule
from src.parser.types import RuleFormat

from .types import DIRECT_EXTRACTION_CONFIDENCE, EntityType, RuleSection


@dataclass(frozen=True, slots=True)
class Entity:
    """One value extracted from a rule, with where it came from."""

    entity_type: EntityType
    value: str
    source_field: str
    location: str
    section: RuleSection
    extractor: str = ""
    confidence: float = DIRECT_EXTRACTION_CONFIDENCE

    def __str__(self) -> str:
        """Return the entity rendered as ``type=value @ location``."""
        return f"{self.entity_type.value}={self.value!r} @ {self.location}"


@dataclass(frozen=True, slots=True)
class ExtractedEntities:
    """Everything extracted from one rule."""

    rule_format: RuleFormat
    entities: tuple[Entity, ...] = ()
    rule_identifier: str | None = None
    rule_title: str = ""

    def __len__(self) -> int:
        """Return how many entities were extracted."""
        return len(self.entities)

    def __iter__(self) -> Iterator[Entity]:
        """Iterate the entities in extraction order."""
        return iter(self.entities)

    @property
    def is_empty(self) -> bool:
        """Return whether nothing was extracted."""
        return not self.entities

    def of_type(self, entity_type: EntityType) -> tuple[Entity, ...]:
        """Return every entity of one type, in extraction order."""
        return tuple(item for item in self.entities if item.entity_type is entity_type)

    def values_of(self, entity_type: EntityType) -> tuple[str, ...]:
        """Return the values of one type, in extraction order.

        Repeated values are kept: this stage does not deduplicate.
        """
        return tuple(item.value for item in self.of_type(entity_type))

    def of_section(self, section: RuleSection) -> tuple[Entity, ...]:
        """Return every entity found in one section of the rule."""
        return tuple(item for item in self.entities if item.section is section)

    def by_extractor(self, name: str) -> tuple[Entity, ...]:
        """Return every entity produced by one extractor."""
        return tuple(item for item in self.entities if item.extractor == name)

    @property
    def present_types(self) -> tuple[EntityType, ...]:
        """Return the types that were extracted, in first-appearance order."""
        seen: list[EntityType] = []
        for item in self.entities:
            if item.entity_type not in seen:
                seen.append(item.entity_type)
        return tuple(seen)

    def grouped(self) -> Mapping[EntityType, tuple[Entity, ...]]:
        """Return the entities grouped by type.

        A view over the same entities. Nothing is merged or dropped.
        """
        groups: dict[EntityType, list[Entity]] = {}
        for item in self.entities:
            groups.setdefault(item.entity_type, []).append(item)
        return MappingProxyType({key: tuple(value) for key, value in groups.items()})

    def with_entities(self, additional: Sequence[Entity]) -> ExtractedEntities:
        """Return a copy with more entities appended."""
        return ExtractedEntities(
            rule_format=self.rule_format,
            entities=(*self.entities, *additional),
            rule_identifier=self.rule_identifier,
            rule_title=self.rule_title,
        )


@dataclass(frozen=True, slots=True)
class FieldOccurrence:
    """One field-and-value pair found while walking a rule's detection body."""

    field: str
    value: str
    location: str
    section: RuleSection = RuleSection.DETECTION


@dataclass(frozen=True, slots=True)
class TextScope:
    """A block of rule text that literal patterns may be scanned over."""

    text: str
    source_field: str
    location: str
    section: RuleSection = RuleSection.DETECTION


@dataclass(frozen=True, slots=True)
class ExtractionContext:
    """The rule, plus the traversals every extractor needs.

    Built once per call and shared by all extractors, so the detection body is
    walked a single time. Nothing here survives the call.
    """

    rule: ParsedRule = field(repr=False)
    occurrences: tuple[FieldOccurrence, ...] = ()
    scopes: tuple[TextScope, ...] = ()

    @property
    def rule_format(self) -> RuleFormat:
        """Return the format of the rule being extracted from."""
        return self.rule.rule_format
