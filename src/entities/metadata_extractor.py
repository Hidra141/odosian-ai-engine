"""Metadata extraction.

Extracts the rule's own descriptive values: authors, tags, references, severity
and status labels, log source taxonomy, index patterns and the detection
timeframe.

Severity and status are reported as :class:`ParsedRule` holds them. Stage-08
already mapped each format's label onto a common vocabulary, and re-deriving
them from the raw document here would duplicate that decision in a second
place. The original labels remain in the rule's preserved raw document.

Titles and descriptions are not extracted. They are prose about the rule rather
than values the rule matches on, and turning sentences into entities would
invent references the detection never made.
"""

from __future__ import annotations

from typing import final

from .base_extractor import values_to_entities
from .models import Entity, ExtractionContext
from .types import EntityType, RuleSection


@final
class MetadataExtractor:
    """Extracts the rule's descriptive and log source values."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "metadata"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (
            EntityType.AUTHOR,
            EntityType.SEVERITY,
            EntityType.STATUS,
            EntityType.TAG,
            EntityType.REFERENCE,
            EntityType.PRODUCT,
            EntityType.CATEGORY,
            EntityType.LOG_SOURCE_SERVICE,
            EntityType.LOG_INDEX,
            EntityType.TIMEFRAME,
        )

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the metadata values found in the rule."""
        rule = context.rule
        found: list[Entity] = []

        found.extend(
            values_to_entities(
                rule.metadata.authors,
                entity_type=EntityType.AUTHOR,
                source_field="author",
                location="metadata.authors",
                section=RuleSection.METADATA,
                extractor=self.name,
            )
        )
        found.extend(
            self._scalar(
                rule.metadata.severity.value,
                EntityType.SEVERITY,
                "severity",
                "metadata.severity",
                RuleSection.METADATA,
            )
        )
        found.extend(
            self._scalar(
                rule.metadata.status.value,
                EntityType.STATUS,
                "status",
                "metadata.status",
                RuleSection.METADATA,
            )
        )
        found.extend(
            values_to_entities(
                rule.tags,
                entity_type=EntityType.TAG,
                source_field="tags",
                location="tags",
                section=RuleSection.TAGS,
                extractor=self.name,
            )
        )
        found.extend(
            values_to_entities(
                rule.references,
                entity_type=EntityType.REFERENCE,
                source_field="references",
                location="references",
                section=RuleSection.REFERENCES,
                extractor=self.name,
            )
        )
        found.extend(self._log_source(context))
        found.extend(
            self._scalar(
                rule.condition.timeframe,
                EntityType.TIMEFRAME,
                "timeframe",
                "condition.timeframe",
                RuleSection.CONDITION,
            )
        )
        return tuple(found)

    def _log_source(self, context: ExtractionContext) -> list[Entity]:
        """Return the log source taxonomy and index patterns."""
        log_source = context.rule.log_source
        found: list[Entity] = []
        for value, entity_type, field in (
            (log_source.product, EntityType.PRODUCT, "product"),
            (log_source.category, EntityType.CATEGORY, "category"),
            (log_source.service, EntityType.LOG_SOURCE_SERVICE, "service"),
        ):
            found.extend(
                self._scalar(
                    value,
                    entity_type,
                    field,
                    f"log_source.{field}",
                    RuleSection.LOG_SOURCE,
                )
            )
        found.extend(
            values_to_entities(
                log_source.indices,
                entity_type=EntityType.LOG_INDEX,
                source_field="index",
                location="log_source.indices",
                section=RuleSection.LOG_SOURCE,
                extractor=self.name,
            )
        )
        return found

    def _scalar(
        self,
        value: str | None,
        entity_type: EntityType,
        source_field: str,
        location: str,
        section: RuleSection,
    ) -> list[Entity]:
        """Return one entity for a scalar value, or nothing when it is unset."""
        if value is None or not value.strip():
            return []
        return [
            Entity(
                entity_type=entity_type,
                value=value,
                source_field=source_field,
                location=location,
                section=section,
                extractor=self.name,
            )
        ]
