"""Entity extraction.

Extraction of cybersecurity entities from parsed rules.

The package reads a :class:`ParsedRule` and reports the values it references,
each with the field it came from and where in the rule it was found. It
extracts and nothing else: it does not resolve identifiers against MITRE
ATT&CK, ECS, Sigma, Elastic, LOLBAS or Atomic Red Team, does not deduplicate or
merge, does not infer values the rule never stated, and does not decide what
anything means. All semantic understanding belongs to Stage-10, Entity Mapping.

Values are preserved exactly as written. An :class:`EntityType` records the kind
of slot a value occupied, not a judgement about the value.

Typical use::

    entities = EntityExtractor().extract(parsed_rule)
    executables = entities.values_of(EntityType.EXECUTABLE)

Adding an entity family means writing one class satisfying :class:`Extractor`
and registering it::

    extractor = EntityExtractor(registry=default_registry().register(MyExtractor()))
"""

from __future__ import annotations

from .base_extractor import (
    Extractor,
    FieldTable,
    PatternTable,
    build_context,
    route_fields,
    scan_shapes,
    split_field,
    values_to_entities,
)
from .command_extractor import CommandExtractor
from .event_extractor import EventExtractor
from .exceptions import (
    EntityExtractionError,
    ExtractionFailureError,
    UnsupportedEntityError,
)
from .extractor import EntityExtractor, default_registry
from .field_extractor import FieldExtractor
from .file_extractor import FileExtractor
from .identity_extractor import IdentityExtractor
from .metadata_extractor import MetadataExtractor
from .models import (
    Entity,
    ExtractedEntities,
    ExtractionContext,
    FieldOccurrence,
    TextScope,
)
from .network_extractor import NetworkExtractor
from .process_extractor import ProcessExtractor
from .registry import ExtractorRegistry
from .registry_extractor import RegistryExtractor
from .types import DIRECT_EXTRACTION_CONFIDENCE, EntityType, RuleSection

__all__ = [
    "DIRECT_EXTRACTION_CONFIDENCE",
    "CommandExtractor",
    "Entity",
    "EntityExtractionError",
    "EntityExtractor",
    "EntityType",
    "EventExtractor",
    "ExtractedEntities",
    "ExtractionContext",
    "ExtractionFailureError",
    "Extractor",
    "ExtractorRegistry",
    "FieldExtractor",
    "FieldOccurrence",
    "FieldTable",
    "FileExtractor",
    "IdentityExtractor",
    "MetadataExtractor",
    "NetworkExtractor",
    "PatternTable",
    "ProcessExtractor",
    "RegistryExtractor",
    "RuleSection",
    "TextScope",
    "UnsupportedEntityError",
    "build_context",
    "default_registry",
    "route_fields",
    "scan_shapes",
    "split_field",
    "values_to_entities",
]
