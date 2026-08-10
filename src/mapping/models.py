"""Entity mapping models.

The mapped entities produced by this stage, and the collection returned to the
caller.

A :class:`MappedEntity` never replaces what Stage-09 extracted. The whole
original entity is held on the mapped one, so the extracted value, its field,
its location, its section and the extractor that found it all survive
canonicalisation. A downstream stage that distrusts a mapping can always fall
back to what the rule actually said.

The collection is a list, not a set. Ordering is preserved, nothing is
deduplicated or merged, and unresolved entities are kept rather than dropped: a
value this layer could not canonicalise is still a value the rule referenced.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from src.entities.models import Entity
from src.entities.types import EntityType, RuleSection
from src.parser.types import RuleFormat

from .types import CanonicalType, MappingMethod, MappingStatus


def _empty_attributes() -> Mapping[str, str]:
    """Return an immutable, empty attribute mapping."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class MappingProvenance:
    """Where a mapped entity came from, carried forward from extraction."""

    original_value: str
    source_field: str
    location: str
    section: RuleSection
    extractor: str
    source_type: EntityType


@dataclass(frozen=True, slots=True)
class MappedEntity:
    """One extracted entity in canonical form, with its original attached."""

    canonical_type: CanonicalType
    original: Entity
    canonical_value: str | None = None
    canonical_id: str | None = None
    canonical_field: str | None = None
    modifiers: tuple[str, ...] = ()
    status: MappingStatus = MappingStatus.UNRESOLVED
    method: MappingMethod = MappingMethod.NONE
    mapper: str = ""
    attributes: Mapping[str, str] = field(default_factory=_empty_attributes)
    note: str = ""

    @property
    def confidence(self) -> float:
        """Return the certainty of this mapping."""
        return self.status.confidence

    @property
    def is_resolved(self) -> bool:
        """Return whether a canonical form was established."""
        return self.status.is_resolved

    @property
    def original_value(self) -> str:
        """Return the value exactly as the rule wrote it."""
        return self.original.value

    @property
    def provenance(self) -> MappingProvenance:
        """Return the extraction provenance of this entity."""
        return MappingProvenance(
            original_value=self.original.value,
            source_field=self.original.source_field,
            location=self.original.location,
            section=self.original.section,
            extractor=self.original.extractor,
            source_type=self.original.entity_type,
        )

    def __str__(self) -> str:
        """Return the mapping rendered for a log line."""
        shown = self.canonical_id or self.canonical_value or self.original.value
        return f"{self.canonical_type.value}={shown!r} [{self.status.value}]"


@dataclass(frozen=True, slots=True)
class MappedEntities:
    """Everything mapped from one rule's extracted entities."""

    rule_format: RuleFormat
    entities: tuple[MappedEntity, ...] = ()
    rule_identifier: str | None = None
    rule_title: str = ""

    def __len__(self) -> int:
        """Return how many entities were mapped."""
        return len(self.entities)

    def __iter__(self) -> Iterator[MappedEntity]:
        """Iterate the entities in mapping order."""
        return iter(self.entities)

    @property
    def is_empty(self) -> bool:
        """Return whether nothing was mapped."""
        return not self.entities

    @property
    def resolved(self) -> tuple[MappedEntity, ...]:
        """Return the entities that reached a canonical form."""
        return tuple(item for item in self.entities if item.is_resolved)

    @property
    def unresolved(self) -> tuple[MappedEntity, ...]:
        """Return the entities that did not, in their original order."""
        return tuple(item for item in self.entities if not item.is_resolved)

    def of_type(self, canonical_type: CanonicalType) -> tuple[MappedEntity, ...]:
        """Return every entity of one canonical type, in order."""
        return tuple(item for item in self.entities if item.canonical_type is canonical_type)

    def of_status(self, status: MappingStatus) -> tuple[MappedEntity, ...]:
        """Return every entity with one mapping status, in order."""
        return tuple(item for item in self.entities if item.status is status)

    def values_of(self, canonical_type: CanonicalType) -> tuple[str, ...]:
        """Return the canonical values of one type, falling back to the original.

        Repeats are kept: this stage does not deduplicate.
        """
        return tuple(
            item.canonical_value if item.canonical_value is not None else item.original.value
            for item in self.of_type(canonical_type)
        )

    def identifiers_of(self, canonical_type: CanonicalType) -> tuple[str, ...]:
        """Return the canonical identifiers of one type, skipping those without one."""
        return tuple(
            item.canonical_id for item in self.of_type(canonical_type) if item.canonical_id
        )

    def by_mapper(self, name: str) -> tuple[MappedEntity, ...]:
        """Return every entity produced by one mapper."""
        return tuple(item for item in self.entities if item.mapper == name)

    @property
    def present_types(self) -> tuple[CanonicalType, ...]:
        """Return the canonical types present, in first-appearance order."""
        seen: list[CanonicalType] = []
        for item in self.entities:
            if item.canonical_type not in seen:
                seen.append(item.canonical_type)
        return tuple(seen)

    def grouped(self) -> Mapping[CanonicalType, tuple[MappedEntity, ...]]:
        """Return the entities grouped by canonical type.

        A view over the same entities. Nothing is merged or dropped.
        """
        groups: dict[CanonicalType, list[MappedEntity]] = {}
        for item in self.entities:
            groups.setdefault(item.canonical_type, []).append(item)
        return MappingProxyType({key: tuple(value) for key, value in groups.items()})

    def with_entities(self, additional: Sequence[MappedEntity]) -> MappedEntities:
        """Return a copy with more entities appended."""
        return MappedEntities(
            rule_format=self.rule_format,
            entities=(*self.entities, *additional),
            rule_identifier=self.rule_identifier,
            rule_title=self.rule_title,
        )
