"""Field extraction.

Extracts the field names a rule references, and the Sigma modifiers applied to
them.

Every detection key yields a field entity, whatever schema it belongs to. This
extractor makes no distinction between a Windows event field, an ECS field and
a field neither schema defines: telling them apart requires knowing the
schemas, which is resolution rather than extraction. The rule's own log source
and format are already recorded, so Stage-10 has what it needs to decide.

For Elastic rules the detection body is a single query string, so dotted
identifiers are recognised lexically. The pattern matches the shape of a dotted
field name and reads nothing around it — no operators, no values, no grouping.
"""

from __future__ import annotations

import re
from typing import Final, final

from .base_extractor import split_field
from .models import Entity, ExtractionContext
from .types import EntityType, RuleSection

_DOTTED_FIELD: Final[re.Pattern[str]] = re.compile(
    r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\b"
)


@final
class FieldExtractor:
    """Extracts referenced field names and their modifiers."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "field"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (EntityType.FIELD, EntityType.FIELD_MODIFIER)

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the fields and modifiers the rule references."""
        found: list[Entity] = []
        for occurrence in context.occurrences:
            if not occurrence.field:
                continue
            base, modifiers = split_field(occurrence.field)
            found.append(
                Entity(
                    entity_type=EntityType.FIELD,
                    value=base,
                    source_field=occurrence.field,
                    location=occurrence.location,
                    section=occurrence.section,
                    extractor=self.name,
                )
            )
            found.extend(
                Entity(
                    entity_type=EntityType.FIELD_MODIFIER,
                    value=modifier,
                    source_field=occurrence.field,
                    location=occurrence.location,
                    section=occurrence.section,
                    extractor=self.name,
                )
                for modifier in modifiers
            )
        found.extend(self._query_fields(context))
        return tuple(found)

    def _query_fields(self, context: ExtractionContext) -> list[Entity]:
        """Return dotted field identifiers found lexically in a query string."""
        query = context.rule.detection.query
        if not query:
            return []
        return [
            Entity(
                entity_type=EntityType.FIELD,
                value=match.group(0),
                source_field="query",
                location=f"detection.query[{match.start()}]",
                section=RuleSection.DETECTION,
                extractor=self.name,
            )
            for match in _DOTTED_FIELD.finditer(query)
        ]
