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
class SuccessorRecord:
    """The knowledge record a redirected seed reached, carried beside the report.

    A redirected seed reaches a real record, and the reader of the result needs
    to know what that record *says*, not merely that it exists. Ranking cannot
    be relied on to deliver it: a redirected seed's node is a graph seed rather
    than an exact identifier match — correctly, because it does not carry the
    identifier the rule wrote — so it forfeits the two heaviest components and
    is outscored by any lexical hit. It is the best *graph* candidate and still
    loses the merged top-k.

    So the record travels with the seed instead of competing for a slot. This
    changes nothing about what retrieval returned: the ranked items, the
    candidate counts and the walk are all exactly what they were. It only means
    the successor's own knowledge cannot be dropped on the way to the context.
    """

    record_id: str
    """The knowledge record's id, so the text can always be traced back."""

    identifier: str
    """The successor's ATT&CK identifier — the current one, never the rule's."""

    name: str
    """What the successor is called, e.g. ``Disable or Modify Tools``."""

    text: str = field(repr=False)
    """The record's own text, as the corpus states it."""

    chunk_ids: tuple[str, ...] = ()
    """The chunks the text was assembled from, in document order."""

    source: KnowledgeSource | None = None
    """The dataset the record belongs to."""

    location: str = ""
    """Where the text sits in that dataset, so the item can be traced home."""

    def __str__(self) -> str:
        """Return the successor rendered for a report line."""
        return f"{self.identifier} {self.name!r} ({self.record_id})"


@dataclass(frozen=True, slots=True)
class SeedReport:
    """What a query entity resolved to in the graph.

    ``value`` is always the identifier the caller asked with, unchanged. When a
    deprecated ATT&CK reference was followed to its current successor,
    ``resolved_value`` names that successor and the status is ``redirected``;
    the two are stated separately so neither can stand in for the other.
    """

    value: str
    status: str
    node_ids: tuple[str, ...] = ()
    note: str = ""
    resolved_value: str | None = None
    """The current identifier a redirected seed reached, or ``None``.

    Set only for a redirected seed. A resolved seed leaves it ``None`` because
    the identifier that reached the node is already ``value``, and repeating it
    would make a redirect and a direct hit look alike.
    """

    resolved_record: SuccessorRecord | None = None
    """The successor's own knowledge record, when the seed was redirected.

    Set only alongside :attr:`resolved_value`, and for the same reason it
    exists: see :class:`SuccessorRecord`. A resolved seed leaves it ``None``,
    because an identifier the corpus carries scores an exact-identifier match
    and its record reaches the result on its own.
    """

    def __str__(self) -> str:
        """Return the seed rendered for a report line."""
        via = f" via {self.resolved_value}" if self.resolved_value else ""
        return f"{self.value} -> {self.status}{via} ({len(self.node_ids)} nodes)"


def redirect_groups(seeds: Sequence[SeedReport]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Return each current identifier with every deprecated one that reached it.

    This is where the collapse stays visible. ``T1562``, ``T1562.001`` and
    ``T1562.006`` all redirect to ``T1685``; the graph seeds that node once,
    which is correct, but a reader of the result must still be able to tell
    three original references collapsed into one node from a rule that named
    ``T1685`` and nothing else. Grouping the reports answers that without
    consulting the rule again.

    Groups are ordered by successor and originals in first-seen order, so two
    runs over one result describe it identically.
    """
    grouped: dict[str, list[str]] = {}
    for seed in seeds:
        if seed.resolved_value is None:
            continue
        originals = grouped.setdefault(seed.resolved_value, [])
        if seed.value not in originals:
            originals.append(seed.value)
    return tuple((current, tuple(grouped[current])) for current in sorted(grouped))


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
