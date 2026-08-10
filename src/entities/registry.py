"""Extractor registry.

Holds the available extractors and answers questions about them.

Unlike the parser registry, this one does not choose *one* member: every
extractor runs on every rule. Selection matters only when a caller asks for a
specific entity type, and for keeping output order stable — entities appear in
registry order, so the same rule always yields the same sequence.

The registry knows no extractor by name. It is constructed with whatever it is
given, so adding an entity family means writing one class that satisfies
:class:`Extractor` and registering it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .base_extractor import Extractor
from .exceptions import UnsupportedEntityError
from .types import EntityType


@dataclass(frozen=True, slots=True)
class ExtractorRegistry:
    """An ordered, immutable collection of extractors."""

    extractors: tuple[Extractor, ...] = ()

    @classmethod
    def of(cls, extractors: Iterable[Extractor]) -> ExtractorRegistry:
        """Build a registry from an iterable, preserving order."""
        return cls(tuple(extractors))

    def register(self, extractor: Extractor) -> ExtractorRegistry:
        """Return a new registry with one extractor appended."""
        return ExtractorRegistry((*self.extractors, extractor))

    @property
    def names(self) -> tuple[str, ...]:
        """Return the extractor names, in run order."""
        return tuple(item.name for item in self.extractors)

    @property
    def supported_types(self) -> tuple[EntityType, ...]:
        """Return every entity type the registry can produce."""
        seen: list[EntityType] = []
        for extractor in self.extractors:
            for entity_type in extractor.entity_types:
                if entity_type not in seen:
                    seen.append(entity_type)
        return tuple(seen)

    def by_name(self, name: str) -> Extractor | None:
        """Return the extractor with a given name, or ``None``."""
        for extractor in self.extractors:
            if extractor.name == name:
                return extractor
        return None

    def producing(self, entity_type: EntityType) -> tuple[Extractor, ...]:
        """Return every extractor that can produce an entity type."""
        found = tuple(
            extractor for extractor in self.extractors if entity_type in extractor.entity_types
        )
        if not found:
            raise UnsupportedEntityError(entity_type, self.supported_types)
        return found
