"""Record normalisation.

Builds a cross-source view of a record beside the record, never in place of it.

Normalisation here is limited to what the record already states: which
identifiers it answers to, its title, its URL, its object type. Each is read
from a named metadata field per source. When a source does not carry one, the
field is listed in ``unknown_fields`` — the corpus has no universal version or
provenance field, and inventing one would give later stages something to trust
that no dataset actually says.

The raw record is carried through untouched, and the raw file is never opened
for writing. Normalisation produces a new object; it does not rewrite anything.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import final

from ..models.records import (
    KnowledgeRecord,
    KnowledgeReference,
    NormalizedKnowledgeRecord,
)
from ..models.types import KnowledgeSource
from .references import references_of

_TITLE_FIELDS: dict[KnowledgeSource, tuple[str, ...]] = {
    KnowledgeSource.MITRE: ("techniqueName", "name"),
    KnowledgeSource.SIGMA: ("title",),
    KnowledgeSource.ELASTIC: ("ruleName",),
    KnowledgeSource.LOLBAS: ("binary", "command"),
    KnowledgeSource.ECS: ("fieldName",),
}

_IDENTIFIER_FIELDS: dict[KnowledgeSource, tuple[str, ...]] = {
    KnowledgeSource.MITRE: ("techniqueId", "id"),
    KnowledgeSource.SIGMA: ("ruleId",),
    KnowledgeSource.ELASTIC: ("ruleId",),
    KnowledgeSource.LOLBAS: (),
    KnowledgeSource.ECS: ("fieldName",),
}


@final
@dataclass(frozen=True, slots=True)
class DefaultKnowledgeNormalizer:
    """Derives the cross-source view of a record."""

    def normalize(self, record: KnowledgeRecord) -> NormalizedKnowledgeRecord:
        """Return the normalized view of one record."""
        unknown: list[str] = []

        title = self._first_string(record, _TITLE_FIELDS.get(record.source, ()))
        if title is None:
            unknown.append("title")

        url = record.metadata_str("url")
        if url is None:
            unknown.append("url")

        object_type = record.metadata_str("objectType")
        if object_type is None:
            unknown.append("object_type")

        identifiers = tuple(self._identifiers(record))
        if not identifiers:
            unknown.append("identifiers")

        return NormalizedKnowledgeRecord(
            record=record,
            canonical_id=record.id,
            identifiers=identifiers,
            title=title,
            url=url,
            object_type=object_type,
            references=self.references_of(record),
            unknown_fields=tuple(unknown),
        )

    def references_of(self, record: KnowledgeRecord) -> tuple[KnowledgeReference, ...]:
        """Return the references a record states, in the order it states them."""
        return references_of(record)

    def _identifiers(self, record: KnowledgeRecord) -> Iterator[str]:
        """Yield every identifier a record answers to, most specific first.

        The envelope id and source id are always included: both are stated by
        the record, and both are used to address it.
        """
        seen: set[str] = set()
        for field in _IDENTIFIER_FIELDS.get(record.source, ()):
            value = record.metadata_str(field)
            if value is not None and value not in seen:
                seen.add(value)
                yield value
        for value in (record.source_id, record.id):
            if value and value not in seen:
                seen.add(value)
                yield value

    def _first_string(self, record: KnowledgeRecord, fields: tuple[str, ...]) -> str | None:
        """Return the first of several metadata fields that holds a string."""
        for field in fields:
            value = record.metadata_str(field)
            if value is not None:
                return value
        return None
