"""Network mapping.

Maps addresses, ports, protocols, domain names and URLs.

Addresses are checked with the standard library rather than a pattern, so
``10.20.30.40`` is confirmed to be an address and ``10.20.30.400`` is not. A
value carrying a prefix length becomes a network rather than an address; both
are canonical forms, and neither is inferred from the other.

Protocols and domain names are lower-cased. Both are case-insensitive by their
own definitions, so the change loses nothing. URLs are left alone: their path
and query are case-sensitive, and normalising the host alone would produce a
value that appears in no rule.
"""

from __future__ import annotations

import ipaddress
from typing import Final, final

from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import exact, normalized, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod

_MAX_PORT: Final[int] = 65535


@final
class NetworkMapper:
    """Maps network indicators."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "network"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (
            EntityType.IP_ADDRESS,
            EntityType.NETWORK_PORT,
            EntityType.NETWORK_PROTOCOL,
            EntityType.DNS_NAME,
            EntityType.URL,
        )

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a network indicator."""
        if entity.entity_type is EntityType.IP_ADDRESS:
            return self._map_address(entity)
        if entity.entity_type is EntityType.NETWORK_PORT:
            return self._map_port(entity)
        if entity.entity_type is EntityType.NETWORK_PROTOCOL:
            return self._lowered(entity, CanonicalType.NETWORK_PROTOCOL)
        if entity.entity_type is EntityType.DNS_NAME:
            return self._lowered(entity, CanonicalType.DOMAIN_NAME)
        return exact(entity, CanonicalType.URL, mapper=self.name)

    def _map_address(self, entity: Entity) -> MappedEntity:
        """Return an address or a network, or nothing when the value is neither."""
        value = entity.value.strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            return exact(
                entity,
                CanonicalType.IP_ADDRESS,
                mapper=self.name,
                canonical_id=str(address),
                attributes={"version": str(address.version)},
            )
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return unresolved(
                entity,
                mapper=self.name,
                note="value is neither an address nor a network",
                canonical_type=CanonicalType.IP_ADDRESS,
                method=MappingMethod.SYNTAX_PATTERN,
            )
        return normalized(
            entity,
            CanonicalType.IP_NETWORK,
            str(network),
            mapper=self.name,
            method=MappingMethod.SYNTAX_PATTERN,
            canonical_id=str(network),
            attributes={"version": str(network.version)},
        )

    def _map_port(self, entity: Entity) -> MappedEntity:
        """Return a port number, or nothing when the value is not one."""
        value = entity.value.strip()
        if not value.isdigit() or not 0 <= int(value) <= _MAX_PORT:
            return unresolved(
                entity,
                mapper=self.name,
                note="value is not a port number between 0 and 65535",
                canonical_type=CanonicalType.NETWORK_PORT,
                method=MappingMethod.SYNTAX_PATTERN,
            )
        return exact(
            entity,
            CanonicalType.NETWORK_PORT,
            mapper=self.name,
            canonical_id=value,
        )

    def _lowered(self, entity: Entity, canonical_type: CanonicalType) -> MappedEntity:
        """Return a value whose canonical form differs only in case."""
        value = entity.value.strip()
        if not value:
            return unresolved(
                entity,
                mapper=self.name,
                note="value is empty",
                canonical_type=canonical_type,
            )
        lowered = value.lower()
        if lowered == entity.value:
            return exact(entity, canonical_type, mapper=self.name)
        return normalized(
            entity,
            canonical_type,
            lowered,
            mapper=self.name,
            method=MappingMethod.CASE_NORMALIZATION,
        )
