"""Process extraction.

Extracts execution objects: processes, executables, services and scheduled
tasks.

Services and scheduled tasks live here because both are execution mechanisms —
each names an image or a command the host will run — not because either is a
process.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from .base_extractor import FieldTable, route_fields
from .models import Entity, ExtractionContext
from .types import EntityType

_FIELDS: Final[FieldTable] = MappingProxyType(
    {
        # Sigma / Windows process creation
        "image": EntityType.EXECUTABLE,
        "parentimage": EntityType.EXECUTABLE,
        "newprocessname": EntityType.EXECUTABLE,
        "parentprocessname": EntityType.EXECUTABLE,
        "originalfilename": EntityType.EXECUTABLE,
        "callerprocessname": EntityType.EXECUTABLE,
        "sourceimage": EntityType.EXECUTABLE,
        "targetimage": EntityType.EXECUTABLE,
        # ECS
        "process.executable": EntityType.EXECUTABLE,
        "process.parent.executable": EntityType.EXECUTABLE,
        "process.pe.original_file_name": EntityType.EXECUTABLE,
        "process.name": EntityType.PROCESS,
        "process.parent.name": EntityType.PROCESS,
        "process.title": EntityType.PROCESS,
        # Services
        "service": EntityType.SERVICE,
        "servicename": EntityType.SERVICE,
        "service.name": EntityType.SERVICE,
        "winlog.event_data.servicename": EntityType.SERVICE,
        "servicefilename": EntityType.EXECUTABLE,
        "imagepath": EntityType.EXECUTABLE,
        # Scheduled tasks
        "taskname": EntityType.SCHEDULED_TASK,
        "task.name": EntityType.SCHEDULED_TASK,
        "winlog.event_data.taskname": EntityType.SCHEDULED_TASK,
    }
)


@final
class ProcessExtractor:
    """Extracts processes, executables, services and scheduled tasks."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "process"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (
            EntityType.PROCESS,
            EntityType.EXECUTABLE,
            EntityType.SERVICE,
            EntityType.SCHEDULED_TASK,
        )

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the execution objects found in the rule."""
        return tuple(route_fields(context, _FIELDS, extractor=self.name))
