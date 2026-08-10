"""Registry mapping.

Maps Windows registry objects, expanding abbreviated hive prefixes.

``HKLM\\`` and ``HKEY_LOCAL_MACHINE\\`` name the same hive. The abbreviations are
a closed, universal set defined by Windows itself, so expanding one into the
other is substitution from a fixed table rather than interpretation. The rest of
the path is left exactly as written: casing, wildcards and separators can all
carry meaning in a rule.

A path whose prefix is not a known hive is left unresolved. It may well be a
relative key fragment, but deciding which hive it belongs to would be a guess.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import exact, normalized, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod

_HIVES: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "hklm": "HKEY_LOCAL_MACHINE",
        "hkcu": "HKEY_CURRENT_USER",
        "hkcr": "HKEY_CLASSES_ROOT",
        "hku": "HKEY_USERS",
        "hkcc": "HKEY_CURRENT_CONFIG",
        "hkey_local_machine": "HKEY_LOCAL_MACHINE",
        "hkey_current_user": "HKEY_CURRENT_USER",
        "hkey_classes_root": "HKEY_CLASSES_ROOT",
        "hkey_users": "HKEY_USERS",
        "hkey_current_config": "HKEY_CURRENT_CONFIG",
    }
)


@final
class RegistryMapper:
    """Maps registry keys, value names and value data."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "registry"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (
            EntityType.REGISTRY_KEY,
            EntityType.REGISTRY_VALUE,
            EntityType.REGISTRY_DATA,
        )

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a registry object."""
        if entity.entity_type is EntityType.REGISTRY_VALUE:
            return exact(entity, CanonicalType.REGISTRY_VALUE_NAME, mapper=self.name)
        if entity.entity_type is EntityType.REGISTRY_DATA:
            return exact(entity, CanonicalType.REGISTRY_VALUE_DATA, mapper=self.name)
        return self._map_key(entity)

    def _map_key(self, entity: Entity) -> MappedEntity:
        """Return a registry key with its hive prefix expanded."""
        value = entity.value
        head, separator, tail = value.partition("\\")
        if not separator:
            return unresolved(
                entity,
                mapper=self.name,
                note="value carries no hive prefix",
                canonical_type=CanonicalType.REGISTRY_KEY,
                method=MappingMethod.SYNTAX_PATTERN,
            )
        hive = _HIVES.get(head.strip().lower())
        if hive is None:
            return unresolved(
                entity,
                mapper=self.name,
                note=f"prefix {head!r} is not a known registry hive",
                canonical_type=CanonicalType.REGISTRY_KEY,
                method=MappingMethod.SYNTAX_PATTERN,
            )
        if hive == head:
            return exact(entity, CanonicalType.REGISTRY_KEY, mapper=self.name)
        return normalized(
            entity,
            CanonicalType.REGISTRY_KEY,
            f"{hive}\\{tail}",
            mapper=self.name,
            method=MappingMethod.ALIAS_TABLE,
            attributes={"hive": hive},
        )
