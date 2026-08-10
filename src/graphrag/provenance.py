"""Retrieval provenance.

Why a chunk exists, and why it was returned.

A retrieval result is only trustworthy if every item can answer both questions
without consulting anything else. A chunk records the record and the byte range
it came from; a retrieved item additionally records which routes found it, what
matched, and the graph path walked to reach it.

Nothing here carries secrets, prompts or generated output.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from src.knowledge.models.types import KnowledgeSource

from .types import MatchKind, RetrievalMethod, SectionType


@dataclass(frozen=True, slots=True)
class ChunkProvenance:
    """Where a chunk came from inside its record."""

    source: KnowledgeSource
    source_id: str
    parent_record_id: str
    dataset: str
    line_number: int
    section: SectionType
    section_label: str
    char_start: int
    char_end: int
    part: int = 1
    part_count: int = 1

    @property
    def location(self) -> str:
        """Return the chunk's location, readable in a report line."""
        return (
            f"{self.dataset}:{self.line_number}:"
            f"{self.section.value}[{self.char_start}:{self.char_end}]"
        )

    def as_properties(self) -> Mapping[str, str]:
        """Return the provenance flattened for storage or logging."""
        return MappingProxyType(
            {
                "source": self.source.value,
                "source_id": self.source_id,
                "parent_record_id": self.parent_record_id,
                "dataset": self.dataset,
                "line": str(self.line_number),
                "section": self.section.value,
                "section_label": self.section_label,
                "char_start": str(self.char_start),
                "char_end": str(self.char_end),
                "part": f"{self.part}/{self.part_count}",
            }
        )


@dataclass(frozen=True, slots=True)
class GraphPathStep:
    """One hop of a graph walk that led to a candidate."""

    start_id: str
    relationship_type: str
    end_id: str
    direction: str

    def __str__(self) -> str:
        """Return the hop rendered as an arrow."""
        arrow = "->" if self.direction == "out" else "<-"
        return f"{self.start_id} {arrow}[{self.relationship_type}]{arrow} {self.end_id}"


@dataclass(frozen=True, slots=True)
class RetrievalEvidence:
    """One reason a chunk was retrieved.

    A chunk found by both routes carries two pieces of evidence, not one merged
    entry, so the routes stay distinguishable.
    """

    method: RetrievalMethod
    match_kind: MatchKind
    detail: str = ""
    matched_terms: tuple[str, ...] = ()
    matched_entities: tuple[str, ...] = ()
    graph_path: tuple[GraphPathStep, ...] = ()
    hops: int = 0
    raw_score: float = 0.0

    def __str__(self) -> str:
        """Return the evidence rendered for a report line."""
        return f"{self.method.value}/{self.match_kind.value}({self.detail})"


@dataclass(frozen=True, slots=True)
class SeedReport:
    """What a query entity resolved to in the graph."""

    value: str
    status: str
    node_ids: tuple[str, ...] = ()
    note: str = ""

    def __str__(self) -> str:
        """Return the seed rendered for a report line."""
        return f"{self.value} -> {self.status} ({len(self.node_ids)} nodes)"


@dataclass(frozen=True, slots=True)
class RetrievalProvenance:
    """The complete account of why one item was returned."""

    source: KnowledgeSource
    source_id: str
    parent_record_id: str
    chunk_id: str
    section: SectionType
    location: str
    methods: tuple[RetrievalMethod, ...] = ()
    evidence: tuple[RetrievalEvidence, ...] = field(default=())

    @property
    def matched_terms(self) -> tuple[str, ...]:
        """Return every distinct term that matched, in first-seen order."""
        return _distinct(term for item in self.evidence for term in item.matched_terms)

    @property
    def matched_entities(self) -> tuple[str, ...]:
        """Return every distinct entity that matched, in first-seen order."""
        return _distinct(item for entry in self.evidence for item in entry.matched_entities)

    @property
    def graph_paths(self) -> tuple[tuple[GraphPathStep, ...], ...]:
        """Return every distinct graph walk that reached this item."""
        return tuple(entry.graph_path for entry in self.evidence if entry.graph_path)


def _distinct(values: object) -> tuple[str, ...]:
    """Return the distinct members of an iterable, in first-seen order."""
    seen: list[str] = []
    for value in values:  # type: ignore[attr-defined]
        if isinstance(value, str) and value not in seen:
            seen.append(value)
    return tuple(seen)


def merge_methods(evidence: Sequence[RetrievalEvidence]) -> tuple[RetrievalMethod, ...]:
    """Return the distinct routes present in a set of evidence, in a fixed order."""
    present = {item.method for item in evidence}
    return tuple(method for method in RetrievalMethod if method in present)
