"""Metadata mapping.

Maps a rule's descriptive values and log source taxonomy.

Severity and status arrive from Stage-08 already expressed in a closed
vocabulary, so mapping them is a conversion into the matching canonical member
rather than a judgement. A value outside that vocabulary — including the
explicit ``unknown`` member — is left unresolved instead of being placed
somewhere plausible.

Log source values are lower-cased, which their taxonomies treat as
insignificant. Index patterns and timeframes are passed through: an index
pattern is matched literally by Elasticsearch, and expanding ``15m`` into
seconds would produce a representation no rule contains.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from src.entities.models import Entity
from src.entities.types import EntityType
from src.parser.types import RuleSeverity, RuleStatus

from .base_mapper import TypeTable, exact, map_by_type, normalized, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod

_PASSTHROUGH: Final[TypeTable] = MappingProxyType(
    {
        EntityType.AUTHOR: CanonicalType.AUTHOR,
        EntityType.LOG_INDEX: CanonicalType.LOG_INDEX,
        EntityType.TIMEFRAME: CanonicalType.TIMEFRAME,
    }
)

_LOWERED: Final[TypeTable] = MappingProxyType(
    {
        EntityType.PRODUCT: CanonicalType.LOG_PRODUCT,
        EntityType.CATEGORY: CanonicalType.LOG_CATEGORY,
        EntityType.LOG_SOURCE_SERVICE: CanonicalType.LOG_SERVICE,
    }
)

_SEVERITIES: Final[frozenset[str]] = frozenset(
    item.value for item in RuleSeverity if item is not RuleSeverity.UNKNOWN
)
_STATUSES: Final[frozenset[str]] = frozenset(
    item.value for item in RuleStatus if item is not RuleStatus.UNKNOWN
)


@final
class MetadataMapper:
    """Maps rule metadata and log source values."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "metadata"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (
            *_PASSTHROUGH,
            *_LOWERED,
            EntityType.SEVERITY,
            EntityType.STATUS,
        )

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a metadata value."""
        if entity.entity_type is EntityType.SEVERITY:
            return self._vocabulary(entity, CanonicalType.SEVERITY_LEVEL, _SEVERITIES)
        if entity.entity_type is EntityType.STATUS:
            return self._vocabulary(entity, CanonicalType.RULE_STATUS, _STATUSES)
        if entity.entity_type in _LOWERED:
            return self._lowered(entity, _LOWERED[entity.entity_type])
        return map_by_type(entity, _PASSTHROUGH, mapper=self.name)

    def _vocabulary(
        self,
        entity: Entity,
        canonical_type: CanonicalType,
        allowed: frozenset[str],
    ) -> MappedEntity:
        """Return a value converted into a closed vocabulary."""
        token = entity.value.strip().lower()
        if token not in allowed:
            return unresolved(
                entity,
                mapper=self.name,
                note=f"value is outside the {canonical_type.value} vocabulary",
                canonical_type=canonical_type,
                method=MappingMethod.ENUM_CONVERSION,
            )
        if token == entity.value:
            return exact(entity, canonical_type, mapper=self.name, canonical_id=token)
        return normalized(
            entity,
            canonical_type,
            token,
            mapper=self.name,
            method=MappingMethod.ENUM_CONVERSION,
            canonical_id=token,
        )

    def _lowered(self, entity: Entity, canonical_type: CanonicalType) -> MappedEntity:
        """Return a taxonomy value whose canonical form differs only in case."""
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
