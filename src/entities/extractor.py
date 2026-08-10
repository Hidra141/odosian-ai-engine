"""Entity extraction entry point.

Walks a parsed rule once, runs every registered extractor over the result, and
returns the entities in registry order.

An extractor that raises anything other than an extraction error is wrapped in
:class:`ExtractionFailureError` naming it, so one misbehaving extractor is
identifiable rather than surfacing as an anonymous failure from somewhere in
the package.

Nothing is deduplicated, merged, sorted or filtered. A value reached by two
routes is reported twice, each with the extractor and location that found it,
because collapsing them would decide they mean the same thing.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import final

from src.parser.models import ParsedRule

from .base_extractor import Extractor, build_context
from .command_extractor import CommandExtractor
from .event_extractor import EventExtractor
from .exceptions import EntityExtractionError, ExtractionFailureError
from .field_extractor import FieldExtractor
from .file_extractor import FileExtractor
from .identity_extractor import IdentityExtractor
from .metadata_extractor import MetadataExtractor
from .models import Entity, ExtractedEntities, ExtractionContext
from .network_extractor import NetworkExtractor
from .process_extractor import ProcessExtractor
from .registry import ExtractorRegistry
from .registry_extractor import RegistryExtractor
from .types import EntityType


def default_registry() -> ExtractorRegistry:
    """Return a registry holding every extractor in the MVP.

    Order fixes the order entities are reported in. Structural extractors run
    before metadata so a reader sees what the rule matches on before what the
    rule says about itself.
    """
    return ExtractorRegistry.of(
        (
            ProcessExtractor(),
            CommandExtractor(),
            FileExtractor(),
            RegistryExtractor(),
            EventExtractor(),
            NetworkExtractor(),
            IdentityExtractor(),
            FieldExtractor(),
            MetadataExtractor(),
        )
    )


@final
@dataclass(frozen=True, slots=True)
class EntityExtractor:
    """Extracts entities from a parsed rule."""

    registry: ExtractorRegistry = field(default_factory=default_registry)

    @property
    def supported_types(self) -> tuple[EntityType, ...]:
        """Return every entity type this extractor can produce."""
        return self.registry.supported_types

    def extract(self, rule: ParsedRule) -> ExtractedEntities:
        """Run every registered extractor over a rule."""
        return self._run(rule, self.registry.extractors)

    def extract_only(
        self,
        rule: ParsedRule,
        entity_types: Sequence[EntityType],
    ) -> ExtractedEntities:
        """Run only the extractors that can produce the requested types.

        Raises :class:`UnsupportedEntityError` when no extractor produces one of
        them. Entities of other types produced incidentally by those extractors
        are dropped, because the caller asked for a subset.
        """
        selected: list[Extractor] = []
        for entity_type in entity_types:
            for extractor in self.registry.producing(entity_type):
                if extractor not in selected:
                    selected.append(extractor)
        wanted = frozenset(entity_types)
        result = self._run(rule, tuple(selected))
        return ExtractedEntities(
            rule_format=result.rule_format,
            entities=tuple(item for item in result.entities if item.entity_type in wanted),
            rule_identifier=result.rule_identifier,
            rule_title=result.rule_title,
        )

    def _run(self, rule: ParsedRule, extractors: Sequence[Extractor]) -> ExtractedEntities:
        """Build the context once and collect entities in extractor order."""
        context = build_context(rule)
        found: list[Entity] = []
        for extractor in extractors:
            found.extend(self._run_one(extractor, context))
        return ExtractedEntities(
            rule_format=rule.rule_format,
            entities=tuple(found),
            rule_identifier=rule.metadata.identifier,
            rule_title=rule.metadata.title,
        )

    def _run_one(
        self,
        extractor: Extractor,
        context: ExtractionContext,
    ) -> tuple[Entity, ...]:
        """Run one extractor, attributing any unexpected failure to it."""
        try:
            return extractor.extract(context)
        except EntityExtractionError:
            raise
        except Exception as error:
            raise ExtractionFailureError(
                extractor.name, f"{type(error).__name__}: {error}"
            ) from error
