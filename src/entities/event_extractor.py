"""Event extraction.

Extracts event identifiers, channels and providers from Windows telemetry, and
event markers from Linux audit telemetry.

Event identifiers are reported as written. ``4688`` stays ``4688``; this stage
does not say what that identifier means, and does not look it up.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from .base_extractor import FieldTable, route_fields
from .models import Entity, ExtractionContext
from .types import EntityType

_FIELDS: Final[FieldTable] = MappingProxyType(
    {
        # Windows identifiers
        "eventid": EntityType.WINDOWS_EVENT_ID,
        "event_id": EntityType.WINDOWS_EVENT_ID,
        "event.code": EntityType.WINDOWS_EVENT_ID,
        "winlog.event_id": EntityType.WINDOWS_EVENT_ID,
        # Windows channels
        "channel": EntityType.WINDOWS_EVENT_CHANNEL,
        "logname": EntityType.WINDOWS_EVENT_CHANNEL,
        "winlog.channel": EntityType.WINDOWS_EVENT_CHANNEL,
        # Windows providers
        "provider_name": EntityType.WINDOWS_EVENT_PROVIDER,
        "providername": EntityType.WINDOWS_EVENT_PROVIDER,
        "source": EntityType.WINDOWS_EVENT_PROVIDER,
        "winlog.provider_name": EntityType.WINDOWS_EVENT_PROVIDER,
        "event.provider": EntityType.WINDOWS_EVENT_PROVIDER,
        # Linux audit
        "syscall": EntityType.LINUX_EVENT,
        "auditd.message_type": EntityType.LINUX_EVENT,
        "auditd.data.syscall": EntityType.LINUX_EVENT,
        "auditd.result": EntityType.LINUX_EVENT,
        "audit.type": EntityType.LINUX_EVENT,
        "type": EntityType.LINUX_EVENT,
    }
)


@final
class EventExtractor:
    """Extracts Windows and Linux event markers."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "event"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (
            EntityType.WINDOWS_EVENT_ID,
            EntityType.WINDOWS_EVENT_CHANNEL,
            EntityType.WINDOWS_EVENT_PROVIDER,
            EntityType.LINUX_EVENT,
        )

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the event markers found in the rule."""
        return tuple(route_fields(context, _FIELDS, extractor=self.name))
