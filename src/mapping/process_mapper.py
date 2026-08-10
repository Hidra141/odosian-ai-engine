"""Process mapping.

Maps execution objects to their canonical types.

Values pass through untouched. A leading backslash on ``\\powershell.exe`` is a
Sigma matching construct, and trailing whitespace in an image path can be the
whole point of an evasion — stripping either would change what the rule said.
Only the type is assigned here.
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
        EntityType.PROCESS: CanonicalType.PROCESS,
        EntityType.EXECUTABLE: CanonicalType.PROCESS_IMAGE,
        EntityType.SERVICE: CanonicalType.SERVICE,
        EntityType.SCHEDULED_TASK: CanonicalType.SCHEDULED_TASK,
    }
)


@final
class ProcessMapper:
    """Maps processes, images, services and scheduled tasks."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "process"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return tuple(_TYPES)

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of an execution object."""
        return map_by_type(entity, _TYPES, mapper=self.name)
