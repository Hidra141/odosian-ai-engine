"""Network extraction.

Extracts addresses, ports, protocols, DNS names and URLs.

Addresses, CIDR ranges and URLs are also recognised by shape, since all three
have forms that need no surrounding syntax to identify. Bare domain names are
deliberately *not* shape-matched: ``powershell.exe`` and ``example.com`` are the
same shape, and guessing between them would manufacture entities. Domains are
extracted only from fields that hold them.
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
        # Addresses
        "destinationip": EntityType.IP_ADDRESS,
        "sourceip": EntityType.IP_ADDRESS,
        "ipaddress": EntityType.IP_ADDRESS,
        "destination.ip": EntityType.IP_ADDRESS,
        "source.ip": EntityType.IP_ADDRESS,
        "client.ip": EntityType.IP_ADDRESS,
        "server.ip": EntityType.IP_ADDRESS,
        "host.ip": EntityType.IP_ADDRESS,
        # Ports
        "destinationport": EntityType.NETWORK_PORT,
        "sourceport": EntityType.NETWORK_PORT,
        "destination.port": EntityType.NETWORK_PORT,
        "source.port": EntityType.NETWORK_PORT,
        # Protocols
        "protocol": EntityType.NETWORK_PROTOCOL,
        "network.protocol": EntityType.NETWORK_PROTOCOL,
        "network.transport": EntityType.NETWORK_PROTOCOL,
        "network.type": EntityType.NETWORK_PROTOCOL,
        # DNS
        "destinationhostname": EntityType.DNS_NAME,
        "queryname": EntityType.DNS_NAME,
        "dns.question.name": EntityType.DNS_NAME,
        "destination.domain": EntityType.DNS_NAME,
        "url.domain": EntityType.DNS_NAME,
        "host.name": EntityType.DNS_NAME,
        # URLs
        "url": EntityType.URL,
        "url.original": EntityType.URL,
        "url.full": EntityType.URL,
        "http.request.referrer": EntityType.URL,
    }
)

_PATTERNS: Final[PatternTable] = MappingProxyType(
    {
        EntityType.URL: re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+"),
        EntityType.IP_ADDRESS: re.compile(
            r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b",
        ),
    }
)


@final
class NetworkExtractor:
    """Extracts network indicators."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "network"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (
            EntityType.IP_ADDRESS,
            EntityType.NETWORK_PORT,
            EntityType.NETWORK_PROTOCOL,
            EntityType.DNS_NAME,
            EntityType.URL,
        )

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the network indicators found in the rule."""
        found = route_fields(context, _FIELDS, extractor=self.name)
        found.extend(scan_shapes(context, _PATTERNS, extractor=self.name, skip_fields=_FIELDS))
        return tuple(found)
