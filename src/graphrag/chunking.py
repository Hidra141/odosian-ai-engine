"""Chunking.

Splits a knowledge record into bounded, addressable pieces.

A record is already a semantic unit, so the default is one chunk. Splitting
happens only when a record exceeds the configured bound, and then it follows the
structure the record already has: the corpus writes ``Label: value`` lines and
labelled blocks, and those labels become section boundaries. A label the section
vocabulary does not recognise keeps the source's own wording and is typed
``OTHER`` — no section is invented that the record did not write.

Where a single section is still too large — the corpus contains a Sigma record
of roughly a quarter of a megabyte — it is cut into ordered parts with a small
overlap, so a match lying across a cut is still found. Parts are numbered, not
renamed, so a chunk always says which part of which section of which record it
is.

Chunk identity is derived from the record id, the section and the part ordinal.
Nothing random is used, so chunking the same record twice produces identical
ids, text and order.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Final, final

from src.knowledge.models.records import KnowledgeRecord
from src.knowledge.models.types import KnowledgeSource

from .config import GraphRagSettings
from .models import Chunk
from .provenance import ChunkProvenance
from .types import SectionType

_LABEL_LINE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<label>[A-Z][A-Za-z0-9 /&()'\-]{1,40}):[ \t]*(?P<rest>.*)$",
    re.MULTILINE,
)

_SECTION_LABELS: Final[dict[str, SectionType]] = {
    "description": SectionType.DESCRIPTION,
    "detection": SectionType.DETECTION,
    "detection logic": SectionType.DETECTION,
    "detection rules": SectionType.DETECTION,
    "condition": SectionType.CONDITION,
    "query": SectionType.QUERY,
    "code": SectionType.COMMAND,
    "command": SectionType.COMMAND,
    "commands": SectionType.COMMAND,
    "usecase": SectionType.USAGE,
    "use case": SectionType.USAGE,
    "usage": SectionType.USAGE,
    "normalize": SectionType.USAGE,
    "example": SectionType.USAGE,
    "false positives": SectionType.FALSE_POSITIVES,
    "falsepositives": SectionType.FALSE_POSITIVES,
    "known false positives": SectionType.FALSE_POSITIVES,
    "tags": SectionType.TAGS,
    "references": SectionType.REFERENCES,
    "reference": SectionType.REFERENCES,
    "url": SectionType.REFERENCES,
    "platform": SectionType.PLATFORMS,
    "platforms": SectionType.PLATFORMS,
    "operating system": SectionType.PLATFORMS,
    "domain": SectionType.PLATFORMS,
    "parent technique": SectionType.RELATIONSHIPS,
    "sub-technique": SectionType.RELATIONSHIPS,
    "tactic(s)": SectionType.RELATIONSHIPS,
    "mitre attack": SectionType.RELATIONSHIPS,
    "attack technique": SectionType.RELATIONSHIPS,
    "threat mapping": SectionType.RELATIONSHIPS,
    "field": SectionType.FIELD,
    "field set": SectionType.FIELD,
    "type": SectionType.FIELD,
    "binary": SectionType.FIELD,
    "log source": SectionType.METADATA,
    "status": SectionType.METADATA,
    "level": SectionType.METADATA,
    "severity": SectionType.METADATA,
    "author": SectionType.METADATA,
    "rule": SectionType.METADATA,
    "sigma rule id": SectionType.METADATA,
    "capability": SectionType.METADATA,
    "index": SectionType.METADATA,
}

_SOURCE_DEFAULT_SECTION: Final[dict[KnowledgeSource, SectionType]] = {
    KnowledgeSource.MITRE: SectionType.DESCRIPTION,
    KnowledgeSource.SIGMA: SectionType.SUMMARY,
    KnowledgeSource.ELASTIC: SectionType.SUMMARY,
    KnowledgeSource.LOLBAS: SectionType.SUMMARY,
    KnowledgeSource.ECS: SectionType.FIELD,
}


@dataclass(frozen=True, slots=True)
class Segment:
    """A labelled stretch of a record's text, before any size bound is applied."""

    section: SectionType
    label: str
    text: str
    start: int
    end: int


@final
@dataclass(frozen=True, slots=True)
class RecordChunker:
    """Turns records into bounded chunks, deterministically."""

    settings: GraphRagSettings

    def chunk(self, record: KnowledgeRecord) -> tuple[Chunk, ...]:
        """Return the chunks of one record, in document order."""
        text = record.text
        if len(text) <= self.settings.max_chunk_chars:
            section = _SOURCE_DEFAULT_SECTION.get(record.source, SectionType.SUMMARY)
            return (self._chunk(record, Segment(section, "record", text, 0, len(text)), 1, 1),)

        chunks: list[Chunk] = []
        counters: dict[SectionType, int] = {}
        for segment in self._segments(record):
            parts = self._split(segment)
            for index, part in enumerate(parts, start=1):
                counters[part.section] = counters.get(part.section, 0) + 1
                chunks.append(self._chunk(record, part, counters[part.section], len(parts), index))
        return tuple(chunks)

    def chunk_all(self, records: Sequence[KnowledgeRecord]) -> tuple[Chunk, ...]:
        """Return the chunks of many records, in record order."""
        produced: list[Chunk] = []
        for record in records:
            produced.extend(self.chunk(record))
        return tuple(produced)

    def _segments(self, record: KnowledgeRecord) -> list[Segment]:
        """Split a record's text at the labels it actually writes."""
        text = record.text
        boundaries: list[tuple[int, SectionType, str]] = []
        for match in _LABEL_LINE.finditer(text):
            label = match.group("label").strip()
            section = _SECTION_LABELS.get(label.lower())
            if section is None:
                continue
            boundaries.append((match.start(), section, label))

        default = _SOURCE_DEFAULT_SECTION.get(record.source, SectionType.SUMMARY)
        if not boundaries:
            return [Segment(default, "record", text, 0, len(text))]

        segments: list[Segment] = []
        first_start = boundaries[0][0]
        if first_start > 0:
            segments.append(Segment(SectionType.SUMMARY, "header", text[:first_start], 0, first_start))
        for index, (start, section, label) in enumerate(boundaries):
            end = boundaries[index + 1][0] if index + 1 < len(boundaries) else len(text)
            body = text[start:end]
            if len(body.strip()) < self.settings.min_chunk_chars and segments:
                previous = segments[-1]
                segments[-1] = Segment(
                    previous.section,
                    previous.label,
                    text[previous.start : end],
                    previous.start,
                    end,
                )
                continue
            segments.append(Segment(section, label, body, start, end))
        return self._coalesce(segments)

    def _coalesce(self, segments: list[Segment]) -> list[Segment]:
        """Merge adjacent segments of the same section into one stretch."""
        merged: list[Segment] = []
        for segment in segments:
            if merged and merged[-1].section is segment.section:
                previous = merged[-1]
                merged[-1] = Segment(
                    previous.section,
                    previous.label,
                    previous.text + segment.text,
                    previous.start,
                    segment.end,
                )
                continue
            merged.append(segment)
        return merged

    def _split(self, segment: Segment) -> list[Segment]:
        """Cut an over-long segment into ordered, overlapping parts."""
        limit = self.settings.max_chunk_chars
        if len(segment.text) <= limit:
            return [segment]
        overlap = min(self.settings.chunk_overlap_chars, max(limit - 1, 0))
        stride = max(limit - overlap, 1)
        parts: list[Segment] = []
        position = 0
        while position < len(segment.text):
            piece = segment.text[position : position + limit]
            parts.append(
                Segment(
                    segment.section,
                    segment.label,
                    piece,
                    segment.start + position,
                    segment.start + position + len(piece),
                )
            )
            if position + limit >= len(segment.text):
                break
            position += stride
        return parts

    def _chunk(
        self,
        record: KnowledgeRecord,
        segment: Segment,
        ordinal: int,
        part_count: int,
        part: int = 1,
    ) -> Chunk:
        """Assemble one chunk with its identity and provenance."""
        chunk_id = f"{record.id}:{segment.section.value}:{ordinal:03d}"
        provenance = ChunkProvenance(
            source=record.source,
            source_id=record.source_id,
            parent_record_id=record.id,
            dataset=record.provenance.path.name if record.provenance else "",
            line_number=record.provenance.line_number if record.provenance else 0,
            section=segment.section,
            section_label=segment.label,
            char_start=segment.start,
            char_end=segment.end,
            part=part,
            part_count=part_count,
        )
        return Chunk(
            chunk_id=chunk_id,
            parent_record_id=record.id,
            source=record.source,
            source_id=record.source_id,
            section=segment.section,
            text=segment.text,
            provenance=provenance,
        )


def iter_chunks(records: Iterator[KnowledgeRecord], settings: GraphRagSettings) -> Iterator[Chunk]:
    """Yield the chunks of a stream of records, without holding them all."""
    chunker = RecordChunker(settings=settings)
    for record in records:
        yield from chunker.chunk(record)
