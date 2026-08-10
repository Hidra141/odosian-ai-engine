"""Entity mapping.

Resolution of extracted entities into canonical identifiers.

The package converts the entities Stage-09 extracted into a canonical,
format-independent representation. It canonicalises *form*, never *meaning*: it
assigns a canonical type, normalises identifier syntax, expands a closed set of
known aliases, and stops there.

**It does not read the knowledge corpora.** No MITRE, ATT&CK, Sigma, Elastic,
LOLBAS or Atomic data is loaded, no JSONL file is opened, no graph is consulted
and no model is called. ``attack.t1059.001`` becomes the identifier
``T1059.001`` by syntax alone; what T1059.001 denotes, and whether it exists, is
Stage-11's question.

When a canonical form cannot be established deterministically, the entity is
returned with :attr:`MappingStatus.UNRESOLVED` and its original intact. A
fabricated mapping is worse than an absent one, because a later stage would
treat it as authoritative.

Typical use::

    mapped = EntityMapper().map(extracted_entities)
    techniques = mapped.identifiers_of(CanonicalType.ATTACK_TECHNIQUE_REFERENCE)

Adding a mapper means writing one class satisfying :class:`Mapper` and
registering it::

    mapper = EntityMapper(registry=default_registry().register(MyMapper()))
"""

from __future__ import annotations

from .base_mapper import (
    AliasTable,
    Mapper,
    TypeTable,
    aliased,
    exact,
    lookup_key,
    map_by_type,
    normalized,
    resolve_alias,
    unresolved,
)
from .command_mapper import CommandMapper
from .entity_mapper import EntityMapper, default_registry
from .event_mapper import EventMapper
from .exceptions import (
    AmbiguousMappingError,
    MappingError,
    MappingFailureError,
    UnsupportedMappingError,
)
from .field_mapper import FieldMapper
from .file_mapper import FileMapper
from .identity_mapper import IdentityMapper
from .metadata_mapper import MetadataMapper
from .models import MappedEntities, MappedEntity, MappingProvenance
from .network_mapper import NetworkMapper
from .process_mapper import ProcessMapper
from .reference_mapper import ReferenceMapper
from .registry import MapperRegistry
from .registry_mapper import RegistryMapper
from .types import CanonicalType, MappingMethod, MappingStatus

__all__ = [
    "AliasTable",
    "AmbiguousMappingError",
    "CanonicalType",
    "CommandMapper",
    "EntityMapper",
    "EventMapper",
    "FieldMapper",
    "FileMapper",
    "IdentityMapper",
    "MappedEntities",
    "MappedEntity",
    "Mapper",
    "MapperRegistry",
    "MappingError",
    "MappingFailureError",
    "MappingMethod",
    "MappingProvenance",
    "MappingStatus",
    "MetadataMapper",
    "NetworkMapper",
    "ProcessMapper",
    "ReferenceMapper",
    "RegistryMapper",
    "TypeTable",
    "UnsupportedMappingError",
    "aliased",
    "default_registry",
    "exact",
    "lookup_key",
    "map_by_type",
    "normalized",
    "resolve_alias",
    "unresolved",
]
