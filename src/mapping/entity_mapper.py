"""Entity mapping entry point.

Runs each extracted entity through the mapper claiming its type and collects the
results in the order they arrived.

An entity whose type no mapper claims is not an error. It becomes an unresolved
mapped entity carrying its original, so the collection returned covers every
entity Stage-09 produced and a later stage never has to reconcile two lists.

A mapper that raises something other than a mapping error is wrapped in
:class:`MappingFailureError` naming it, so one misbehaving mapper is
identifiable rather than surfacing anonymously.

Strict mode turns an ambiguity into :class:`AmbiguousMappingError`. It is off by
default, because the correct answer to an ambiguity is to record it rather than
to fail, and a caller who would rather stop can ask for that explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import final

from src.entities.models import Entity, ExtractedEntities

from .base_mapper import Mapper, unresolved
from .command_mapper import CommandMapper
from .event_mapper import EventMapper
from .exceptions import AmbiguousMappingError, MappingError, MappingFailureError
from .field_mapper import FieldMapper
from .file_mapper import FileMapper
from .identity_mapper import IdentityMapper
from .metadata_mapper import MetadataMapper
from .models import MappedEntities, MappedEntity
from .network_mapper import NetworkMapper
from .process_mapper import ProcessMapper
from .reference_mapper import ReferenceMapper
from .registry import MapperRegistry
from .registry_mapper import RegistryMapper
from .types import MappingMethod

_UNMAPPED_NOTE = "no mapper claims this entity type"


def default_registry() -> MapperRegistry:
    """Return a registry holding every mapper in the MVP.

    Order is the order mappers are consulted. The reference mapper precedes the
    metadata mapper so that tags and references reach identifier normalisation
    rather than being treated as plain metadata.
    """
    return MapperRegistry.of(
        (
            ProcessMapper(),
            CommandMapper(),
            FileMapper(),
            RegistryMapper(),
            EventMapper(),
            NetworkMapper(),
            IdentityMapper(),
            FieldMapper(),
            ReferenceMapper(),
            MetadataMapper(),
        )
    )


@final
@dataclass(frozen=True, slots=True)
class EntityMapper:
    """Maps extracted entities into canonical form."""

    registry: MapperRegistry = field(default_factory=default_registry)
    strict: bool = False

    @property
    def supported_types(self) -> tuple[object, ...]:
        """Return every extracted entity type this mapper can handle."""
        return self.registry.supported_types

    def map(self, extracted: ExtractedEntities) -> MappedEntities:
        """Map every extracted entity, preserving order."""
        return MappedEntities(
            rule_format=extracted.rule_format,
            entities=tuple(self.map_entity(entity) for entity in extracted),
            rule_identifier=extracted.rule_identifier,
            rule_title=extracted.rule_title,
        )

    def map_entity(self, entity: Entity) -> MappedEntity:
        """Map one entity, or record that nothing claims it."""
        mapper = self.registry.find(entity.entity_type)
        if mapper is None:
            return unresolved(entity, mapper="", note=_UNMAPPED_NOTE)
        mapped = self._run(mapper, entity)
        if self.strict and mapped.method is MappingMethod.AMBIGUOUS:
            raise AmbiguousMappingError(entity.value, ())
        return mapped

    def _run(self, mapper: Mapper, entity: Entity) -> MappedEntity:
        """Run one mapper, attributing any unexpected failure to it."""
        try:
            return mapper.map(entity)
        except MappingError:
            raise
        except Exception as error:
            raise MappingFailureError(
                mapper.name, f"{type(error).__name__}: {error}"
            ) from error
