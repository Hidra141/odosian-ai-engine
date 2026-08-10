"""Mapper contract and shared constructors.

Defines the interface a mapper satisfies, and the four ways a mapped entity is
built. Every mapper reaches for one of these rather than constructing a
:class:`MappedEntity` by hand, so status, method and provenance stay consistent
across the package.

Alias tables map a lookup key to a *tuple* of candidates. One candidate resolves;
several are an ambiguity, which produces an unresolved entity rather than a
choice. That shape is deliberate: a table that could only hold one answer would
make ambiguity impossible to express, and the temptation would be to pick.

Lookup keys are lower-cased and stripped. That normalisation applies to the key
used for the lookup only — the value stored on the entity, and the original
entity itself, are never altered by it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from src.entities.models import Entity
from src.entities.types import EntityType

from .models import MappedEntity
from .types import CanonicalType, MappingMethod, MappingStatus

AliasTable = Mapping[str, tuple[CanonicalType, ...]]
TypeTable = Mapping[EntityType, CanonicalType]


@runtime_checkable
class Mapper(Protocol):
    """Maps one family of extracted entities into canonical form."""

    @property
    def name(self) -> str:
        """Return this mapper's identifier, recorded on every entity it makes."""
        ...

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        ...

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of one entity.

        Must never raise for a value it cannot canonicalise. Returning an
        unresolved entity is the correct answer in that case; an exception means
        the mapper itself could not run.
        """
        ...


def lookup_key(text: str) -> str:
    """Return the form of a value used to index an alias table."""
    return text.strip().lower()


def exact(
    entity: Entity,
    canonical_type: CanonicalType,
    *,
    mapper: str,
    canonical_id: str | None = None,
    attributes: Mapping[str, str] | None = None,
) -> MappedEntity:
    """Build a mapping that assigns a type and leaves the value untouched."""
    return MappedEntity(
        canonical_type=canonical_type,
        original=entity,
        canonical_value=entity.value,
        canonical_id=canonical_id,
        status=MappingStatus.EXACT,
        method=MappingMethod.DIRECT_TYPE,
        mapper=mapper,
        attributes=attributes if attributes is not None else {},
    )


def normalized(
    entity: Entity,
    canonical_type: CanonicalType,
    canonical_value: str,
    *,
    mapper: str,
    method: MappingMethod,
    canonical_id: str | None = None,
    canonical_field: str | None = None,
    modifiers: tuple[str, ...] = (),
    attributes: Mapping[str, str] | None = None,
) -> MappedEntity:
    """Build a mapping whose value was reshaped by a defined structural rule."""
    return MappedEntity(
        canonical_type=canonical_type,
        original=entity,
        canonical_value=canonical_value,
        canonical_id=canonical_id,
        canonical_field=canonical_field,
        modifiers=modifiers,
        status=MappingStatus.NORMALIZED,
        method=method,
        mapper=mapper,
        attributes=attributes if attributes is not None else {},
    )


def aliased(
    entity: Entity,
    canonical_type: CanonicalType,
    *,
    mapper: str,
    canonical_value: str | None = None,
    canonical_field: str | None = None,
    modifiers: tuple[str, ...] = (),
) -> MappedEntity:
    """Build a mapping resolved through a known alias table."""
    return MappedEntity(
        canonical_type=canonical_type,
        original=entity,
        canonical_value=canonical_value if canonical_value is not None else entity.value,
        canonical_field=canonical_field,
        modifiers=modifiers,
        status=MappingStatus.ALIAS,
        method=MappingMethod.ALIAS_TABLE,
        mapper=mapper,
    )


def unresolved(
    entity: Entity,
    *,
    mapper: str,
    note: str,
    canonical_type: CanonicalType = CanonicalType.UNKNOWN,
    method: MappingMethod = MappingMethod.NONE,
    canonical_field: str | None = None,
    modifiers: tuple[str, ...] = (),
) -> MappedEntity:
    """Build a mapping that establishes no canonical form.

    The original entity is preserved in full. ``note`` records why nothing was
    established, so a reader can tell a value that fell outside every table from
    one that matched several.
    """
    return MappedEntity(
        canonical_type=canonical_type,
        original=entity,
        canonical_value=None,
        canonical_field=canonical_field,
        modifiers=modifiers,
        status=MappingStatus.UNRESOLVED,
        method=method,
        mapper=mapper,
        note=note,
    )


def resolve_alias(table: AliasTable, key: str) -> tuple[CanonicalType, ...]:
    """Return the candidates a lookup key resolves to, possibly none."""
    return table.get(lookup_key(key), ())


def map_by_type(
    entity: Entity,
    table: TypeTable,
    *,
    mapper: str,
) -> MappedEntity:
    """Map an entity whose canonical type follows from its extracted type."""
    canonical_type = table.get(entity.entity_type)
    if canonical_type is None:
        return unresolved(
            entity,
            mapper=mapper,
            note=f"no canonical type registered for {entity.entity_type.value!r}",
        )
    return exact(entity, canonical_type, mapper=mapper)
