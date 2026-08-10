"""Entity mapping exceptions.

Every failure leaving this package is one of these types.

An unresolved mapping is not a failure. A value this layer cannot canonicalise
without guessing is reported as an entity with
:attr:`MappingStatus.UNRESOLVED`, with the original preserved. These exceptions
are reserved for a mapper that could not run, a caller that asked for something
the registry cannot do, or an ambiguity a caller explicitly asked to be told
about.
"""

from __future__ import annotations

from collections.abc import Sequence

from src.entities.types import EntityType

from .types import CanonicalType


class MappingError(Exception):
    """Base class for every entity mapping failure."""


class UnsupportedMappingError(MappingError):
    """No registered mapper handles the requested entity type."""

    def __init__(self, entity_type: EntityType, supported: Sequence[EntityType]) -> None:
        """Record the requested type and what the registry can map."""
        names = ", ".join(sorted(item.value for item in supported)) or "none"
        super().__init__(
            f"No mapper handles {entity_type.value!r}; registered types: {names}"
        )
        self.entity_type = entity_type
        self.supported = tuple(supported)


class AmbiguousMappingError(MappingError):
    """More than one canonical form applied and strict mapping was requested.

    Raised only in strict mode. By default an ambiguity produces an unresolved
    entity instead, because choosing between candidates would be a guess.
    """

    def __init__(self, value: str, candidates: Sequence[CanonicalType]) -> None:
        """Record the value and every canonical form that applied to it."""
        names = ", ".join(item.value for item in candidates)
        super().__init__(f"Value {value!r} maps to more than one canonical type: {names}")
        self.value = value
        self.candidates = tuple(candidates)


class MappingFailureError(MappingError):
    """A mapper failed while mapping an entity."""

    def __init__(self, mapper: str, reason: str) -> None:
        """Record which mapper failed and why."""
        super().__init__(f"Mapper {mapper!r} failed: {reason}")
        self.mapper = mapper
        self.reason = reason
