"""Command mapping.

Maps command lines and arguments to their canonical types.

Command values are never altered, not even by whitespace normalisation. A Sigma
rule matching ``' -enc '`` depends on the surrounding spaces to avoid matching
``-encoding``; trimming them would silently widen the rule. The value is carried
through byte for byte and only the type is assigned.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import TypeTable, map_by_type
from .models import MappedEntity
from .types import CanonicalType

_TYPES: Final[TypeTable] = MappingProxyType(
    {
        EntityType.COMMAND_LINE: CanonicalType.COMMAND_LINE,
        EntityType.COMMAND_ARGUMENT: CanonicalType.COMMAND_ARGUMENT,
    }
)


@final
class CommandMapper:
    """Maps command lines and command arguments."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "command"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return tuple(_TYPES)

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a command value."""
        return map_by_type(entity, _TYPES, mapper=self.name)
