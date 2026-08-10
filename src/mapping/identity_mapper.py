"""Identity mapping.

Maps users and groups, separating security identifiers from account names.

A security identifier has a fixed syntax — ``S`` followed by a revision,
authority and sub-authorities — which is recognisable without consulting
anything. That syntax is the only thing distinguishing the two forms here.
Which account an identifier denotes is not established: ``S-1-5-18`` is recorded
as a security identifier and nothing more.

Account names are passed through unchanged. The domain prefix in
``NT AUTHORITY\\SYSTEM`` is part of the name a rule matched on, and separating
it would produce a value the rule never wrote.
"""

from __future__ import annotations

import re
from typing import Final, final

from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import exact, normalized, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod

_SECURITY_IDENTIFIER: Final[re.Pattern[str]] = re.compile(
    r"\AS-\d+-\d+(?:-\d+)*\Z",
    re.IGNORECASE,
)


@final
class IdentityMapper:
    """Maps users, security identifiers and groups."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "identity"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (EntityType.USER, EntityType.GROUP)

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of an identity value."""
        value = entity.value.strip()
        if not value:
            return unresolved(entity, mapper=self.name, note="value is empty")
        if entity.entity_type is EntityType.GROUP:
            return exact(entity, CanonicalType.GROUP, mapper=self.name)
        if _SECURITY_IDENTIFIER.match(value):
            return self._map_identifier(entity, value)
        return exact(entity, CanonicalType.USER_ACCOUNT, mapper=self.name)

    def _map_identifier(self, entity: Entity, value: str) -> MappedEntity:
        """Return a security identifier in its conventional upper-case form."""
        canonical = value.upper()
        if canonical == entity.value:
            return exact(
                entity,
                CanonicalType.SECURITY_IDENTIFIER,
                mapper=self.name,
                canonical_id=canonical,
            )
        return normalized(
            entity,
            CanonicalType.SECURITY_IDENTIFIER,
            canonical,
            mapper=self.name,
            method=MappingMethod.CASE_NORMALIZATION,
            canonical_id=canonical,
        )
