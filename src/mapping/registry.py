"""Mapper registry.

Holds the available mappers and selects one per extracted entity type.

Selection is deterministic: the first registered mapper claiming a type wins,
and registration order is preserved, so the same input always produces the same
output in the same order.

The registry is immutable. :meth:`register` returns a new registry, so no
module-level collection accumulates mappers over the life of a process and no
caller can alter another caller's registry.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from src.entities.types import EntityType

from .base_mapper import Mapper
from .exceptions import UnsupportedMappingError


@dataclass(frozen=True, slots=True)
class MapperRegistry:
    """An ordered, immutable collection of mappers."""

    mappers: tuple[Mapper, ...] = ()

    @classmethod
    def of(cls, mappers: Iterable[Mapper]) -> MapperRegistry:
        """Build a registry from an iterable, preserving order."""
        return cls(tuple(mappers))

    def register(self, mapper: Mapper) -> MapperRegistry:
        """Return a new registry with one mapper appended.

        The receiver is unchanged. A later mapper claiming a type another mapper
        already claims will not be selected for it, since the first match wins.
        """
        return MapperRegistry((*self.mappers, mapper))

    @property
    def names(self) -> tuple[str, ...]:
        """Return the mapper names, in registration order."""
        return tuple(item.name for item in self.mappers)

    @property
    def supported_types(self) -> tuple[EntityType, ...]:
        """Return every extracted entity type the registry can map."""
        seen: list[EntityType] = []
        for mapper in self.mappers:
            for entity_type in mapper.source_types:
                if entity_type not in seen:
                    seen.append(entity_type)
        return tuple(seen)

    def find(self, entity_type: EntityType) -> Mapper | None:
        """Return the mapper claiming a type, or ``None`` when none does."""
        for mapper in self.mappers:
            if entity_type in mapper.source_types:
                return mapper
        return None

    def for_type(self, entity_type: EntityType) -> Mapper:
        """Return the mapper claiming a type, raising when none does."""
        mapper = self.find(entity_type)
        if mapper is None:
            raise UnsupportedMappingError(entity_type, self.supported_types)
        return mapper

    def by_name(self, name: str) -> Mapper | None:
        """Return the mapper with a given name, or ``None``."""
        for mapper in self.mappers:
            if mapper.name == name:
                return mapper
        return None
