"""Event mapping.

Maps event identifiers, channels, providers and Linux audit markers.

An event identifier is canonical only when it is a plain number. Sigma also
allows ranges and lists in that field, and a value that is not a single integer
is left unresolved rather than coerced into one. What ``4688`` denotes is not
decided here: this layer records that it is an event identifier and stops.
"""

from __future__ import annotations

from typing import final

from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import exact, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod


@final
class EventMapper:
    """Maps Windows and Linux event markers."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "event"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (
            EntityType.WINDOWS_EVENT_ID,
            EntityType.WINDOWS_EVENT_CHANNEL,
            EntityType.WINDOWS_EVENT_PROVIDER,
            EntityType.LINUX_EVENT,
        )

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of an event marker."""
        if entity.entity_type is EntityType.WINDOWS_EVENT_ID:
            return self._map_identifier(entity)
        if entity.entity_type is EntityType.WINDOWS_EVENT_CHANNEL:
            return exact(entity, CanonicalType.EVENT_CHANNEL, mapper=self.name)
        if entity.entity_type is EntityType.WINDOWS_EVENT_PROVIDER:
            return exact(entity, CanonicalType.EVENT_PROVIDER, mapper=self.name)
        return exact(entity, CanonicalType.LINUX_AUDIT_EVENT, mapper=self.name)

    def _map_identifier(self, entity: Entity) -> MappedEntity:
        """Return an event identifier, or nothing when it is not a single number."""
        value = entity.value.strip()
        if not value.isdigit():
            return unresolved(
                entity,
                mapper=self.name,
                note="value is not a single numeric event identifier",
                canonical_type=CanonicalType.EVENT_ID,
                method=MappingMethod.SYNTAX_PATTERN,
            )
        return exact(entity, CanonicalType.EVENT_ID, mapper=self.name, canonical_id=value)
