"""Identity extraction.

Extracts users and groups.

Security identifiers are extracted as users because that is the slot they
occupy, not because this stage resolved one to an account. ``S-1-5-18`` is
reported verbatim; deciding it names the SYSTEM account is Stage-10's work.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from .base_extractor import FieldTable, route_fields
from .models import Entity, ExtractionContext
from .types import EntityType

_FIELDS: Final[FieldTable] = MappingProxyType(
    {
        # Users
        "user": EntityType.USER,
        "username": EntityType.USER,
        "accountname": EntityType.USER,
        "subjectusername": EntityType.USER,
        "targetusername": EntityType.USER,
        "subjectusersid": EntityType.USER,
        "targetusersid": EntityType.USER,
        "user.name": EntityType.USER,
        "user.id": EntityType.USER,
        "user.email": EntityType.USER,
        "winlog.event_data.subjectusername": EntityType.USER,
        "winlog.event_data.targetusername": EntityType.USER,
        # Groups
        "group": EntityType.GROUP,
        "groupname": EntityType.GROUP,
        "targetgroupname": EntityType.GROUP,
        "group.name": EntityType.GROUP,
        "group.id": EntityType.GROUP,
        "user.group.name": EntityType.GROUP,
    }
)


@final
class IdentityExtractor:
    """Extracts users and groups."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "identity"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (EntityType.USER, EntityType.GROUP)

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the users and groups found in the rule."""
        return tuple(route_fields(context, _FIELDS, extractor=self.name))
