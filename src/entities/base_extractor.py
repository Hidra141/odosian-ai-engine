"""Extractor contract and shared machinery.

Defines the interface an extractor satisfies, the traversal that turns a parsed
rule into flat occurrences, and the two routes by which a value becomes an
entity.

**Field routing** — a value is extracted because of the field it sat in. Each
extractor owns a small table of literal field names. The table is a routing
hint, not a schema: nothing is canonicalised, no definition is looked up, and
the field name is recorded on the entity exactly as the rule wrote it. Lookup
is case-insensitive because formats disagree on casing; the stored value and
field are untouched.

**Shape scanning** — a value is extracted because of its literal form. An IPv4
address or a 64-character hex string is recognisable without reading any
surrounding syntax. Scanning never interprets operators, grouping or negation,
so it says nothing about what the rule does with the value.

Elastic rules need the second route: Stage-08 leaves their whole query in a
single string, so field routing alone would find nothing in them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Final, Protocol, runtime_checkable

from src.parser.models import ParsedRule
from src.parser.types import RuleValue

from .models import Entity, ExtractionContext, FieldOccurrence, TextScope
from .types import EntityType, RuleSection

MODIFIER_SEPARATOR: Final[str] = "|"

FieldTable = Mapping[str, EntityType]
PatternTable = Mapping[EntityType, re.Pattern[str]]


@runtime_checkable
class Extractor(Protocol):
    """Extracts one family of entities from a rule."""

    @property
    def name(self) -> str:
        """Return this extractor's identifier, recorded on every entity it makes."""
        ...

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        ...

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the entities found in the rule, in the order they were found."""
        ...


def split_field(key: str) -> tuple[str, tuple[str, ...]]:
    """Split a Sigma field key into its base name and its modifiers.

    ``Image|endswith`` becomes ``("Image", ("endswith",))``. Both parts are
    returned exactly as written; this decomposes the key along the separator
    the format defines, and changes neither part.
    """
    if MODIFIER_SEPARATOR not in key:
        return key, ()
    head, _, tail = key.partition(MODIFIER_SEPARATOR)
    modifiers = tuple(part for part in tail.split(MODIFIER_SEPARATOR) if part)
    return head, modifiers


def build_context(rule: ParsedRule) -> ExtractionContext:
    """Walk a parsed rule once and return the context extractors share."""
    occurrences = tuple(_walk_detection(rule))
    scopes = tuple(_text_scopes(rule, occurrences))
    return ExtractionContext(rule=rule, occurrences=occurrences, scopes=scopes)


def route_fields(
    context: ExtractionContext,
    table: FieldTable,
    *,
    extractor: str,
) -> list[Entity]:
    """Emit an entity for each occurrence whose base field is in the table."""
    found: list[Entity] = []
    for occurrence in context.occurrences:
        base, _ = split_field(occurrence.field)
        entity_type = table.get(base.strip().lower())
        if entity_type is None:
            continue
        found.append(
            Entity(
                entity_type=entity_type,
                value=occurrence.value,
                source_field=occurrence.field,
                location=occurrence.location,
                section=occurrence.section,
                extractor=extractor,
            )
        )
    return found


def scan_shapes(
    context: ExtractionContext,
    patterns: PatternTable,
    *,
    extractor: str,
    skip_fields: FieldTable | None = None,
) -> list[Entity]:
    """Emit an entity for each literal shape found in the rule's text.

    ``skip_fields`` suppresses scanning of values this extractor already routed
    by field name, so one extractor does not report the same value twice.
    Suppression is local: a value found by a *different* extractor is still
    reported, because deduplication across extractors is forbidden.
    """
    found: list[Entity] = []
    for scope in context.scopes:
        if skip_fields is not None:
            base, _ = split_field(scope.source_field)
            if base.strip().lower() in skip_fields:
                continue
        for entity_type, pattern in patterns.items():
            for match in pattern.finditer(scope.text):
                found.append(
                    Entity(
                        entity_type=entity_type,
                        value=match.group(0),
                        source_field=scope.source_field,
                        location=scope.location,
                        section=scope.section,
                        extractor=extractor,
                    )
                )
    return found


def values_to_entities(
    values: Iterable[str],
    *,
    entity_type: EntityType,
    source_field: str,
    location: str,
    section: RuleSection,
    extractor: str,
) -> list[Entity]:
    """Emit one entity per value in a plain sequence, preserving order."""
    return [
        Entity(
            entity_type=entity_type,
            value=value,
            source_field=source_field,
            location=f"{location}[{index}]",
            section=section,
            extractor=extractor,
        )
        for index, value in enumerate(values)
    ]


def _walk_detection(rule: ParsedRule) -> list[FieldOccurrence]:
    """Flatten the detection body into field-and-value pairs."""
    found: list[FieldOccurrence] = []
    for name, block in rule.detection.definitions.items():
        _walk(block, field="", path=f"detection.{name}", found=found)
    return found


def _walk(value: RuleValue, *, field: str, path: str, found: list[FieldOccurrence]) -> None:
    """Recurse through a detection block, collecting scalar leaves."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = str(key)
            _walk(item, field=child, path=f"{path}.{child}", found=found)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _walk(item, field=field, path=f"{path}[{index}]", found=found)
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (str, int, float)):
        found.append(FieldOccurrence(field=field, value=str(value), location=path))


def _text_scopes(rule: ParsedRule, occurrences: Sequence[FieldOccurrence]) -> list[TextScope]:
    """Return the text blocks literal patterns may be scanned over.

    Detection values and the query only. Titles, descriptions and references are
    prose or already extracted elsewhere, and scanning them would manufacture
    entities the detection never referenced.
    """
    scopes = [
        TextScope(
            text=occurrence.value,
            source_field=occurrence.field,
            location=occurrence.location,
        )
        for occurrence in occurrences
    ]
    if rule.detection.query:
        scopes.append(
            TextScope(
                text=rule.detection.query,
                source_field="query",
                location="detection.query",
            )
        )
    return scopes
