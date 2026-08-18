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

from .base_extractor import introduces_a_value, split_field
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
        """Return dotted identifiers a query names outside any clause it states.

        The sweep is lexical and cannot tell a field from a value: a lowercase
        filename and a dotted field name have the same shape, which is how
        ``powershell.exe`` came to be reported as a field. Anything the clause
        reader has already paired is therefore left to it, since that reading
        knows which side of the separator the text sat on and this one does not.

        What remains is a dotted name a clause names but the reader could not
        pair — an unterminated group, say. It is still reported, because the
        separator proves a field was written there, but it carries ``query`` as
        its source: the sweep does not know which values belonged to it, and
        naming one would be the guess this avoids.

        A token with no separator after it is a value, whatever its shape.
        ``lsass.exe``, ``blogspot.com`` and ``rc.local`` are indistinguishable
        from field names by spelling alone, and distinguishable from them by the
        one thing the query does state: what follows. Nothing is matched against
        a list of extensions or hosts, because such a list would be a guess about
        vocabulary rather than a reading of syntax.
        """
        query = context.rule.detection.query
        if not query:
            return []
        stated = {item.field for item in context.occurrences}
        stated.update(item.value for item in context.occurrences)
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
            if match.group(0) not in stated
            and introduces_a_value(query, match.end())
        ]
