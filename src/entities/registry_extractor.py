"""Registry extraction.

Extracts Windows registry keys, value names and value data.

Keys are also recognised by shape: a string opening with a hive prefix is a
registry path wherever it appears. The prefix is matched as written, so both
``HKLM\\`` and ``HKEY_LOCAL_MACHINE\\`` forms are extracted and neither is
rewritten into the other.
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Final, final

from .base_extractor import FieldTable, PatternTable, route_fields, scan_shapes
from .models import Entity, ExtractionContext
from .types import EntityType

_FIELDS: Final[FieldTable] = MappingProxyType(
    {
        # Sigma / Sysmon
        "targetobject": EntityType.REGISTRY_KEY,
        "objectname": EntityType.REGISTRY_KEY,
        "newname": EntityType.REGISTRY_KEY,
        "valuename": EntityType.REGISTRY_VALUE,
        "details": EntityType.REGISTRY_DATA,
        "newvalue": EntityType.REGISTRY_DATA,
        # ECS
        "registry.path": EntityType.REGISTRY_KEY,
        "registry.key": EntityType.REGISTRY_KEY,
        "registry.hive": EntityType.REGISTRY_KEY,
        "registry.value": EntityType.REGISTRY_VALUE,
        "registry.data.strings": EntityType.REGISTRY_DATA,
        "registry.data.bytes": EntityType.REGISTRY_DATA,
    }
)

_PATTERNS: Final[PatternTable] = MappingProxyType(
    {
        EntityType.REGISTRY_KEY: re.compile(
            r"(?:HKLM|HKCU|HKCR|HKU|HKCC"
            r"|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT"
            r"|HKEY_USERS|HKEY_CURRENT_CONFIG"
            r"|\\REGISTRY\\[A-Za-z]+)"
            r"[\\\\/][^\s\"']*",
            re.IGNORECASE,
        ),
    }
)


@final
class RegistryExtractor:
    """Extracts registry keys, value names and value data."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "registry"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (
            EntityType.REGISTRY_KEY,
            EntityType.REGISTRY_VALUE,
            EntityType.REGISTRY_DATA,
        )

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the registry objects found in the rule."""
        found = route_fields(context, _FIELDS, extractor=self.name)
        found.extend(scan_shapes(context, _PATTERNS, extractor=self.name, skip_fields=_FIELDS))
        return tuple(found)
