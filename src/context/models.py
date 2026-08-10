"""Context models.

The immutable value objects a context package is made of.

Every item carries the chain back to the dataset line that produced it:
context item → retrieval chunk → parent record → source dataset, plus the graph
path where traversal was involved. A downstream stage that doubts a claim can
always follow it home.

The models hold data and answer questions about it. They read no files, perform
no retrieval, call no model, and contain no judgement about what the evidence
means.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from src.knowledge.models.types import KnowledgeSource

from .types import (
    SECTION_ORDER,
    ContextOperation,
    EvidenceKind,
    EvidencePriority,
    EvidenceStatus,
    SectionName,
    TruncationPolicy,
    WarningCode,
)


def _empty_metadata() -> Mapping[str, str]:
    """Return an immutable, empty metadata mapping."""
    return MappingProxyType({})


_REPORT_SECTIONS: frozenset[SectionName] = frozenset(
    {SectionName.WARNINGS, SectionName.METADATA}
)
"""Sections that describe the package rather than fill it, and so escape the budget."""


@dataclass(frozen=True, slots=True)
class GraphTrace:
    """One traversal step preserved from retrieval evidence."""

    start_id: str
    relationship_type: str
    end_id: str
    direction: str
    hops: int = 0

    def __str__(self) -> str:
        """Return the step rendered as an arrow."""
        arrow = "->" if self.direction == "out" else "<-"
        return f"{self.start_id} {arrow}[{self.relationship_type}]{arrow} {self.end_id}"


@dataclass(frozen=True, slots=True)
class ItemProvenance:
    """Where a context item came from, end to end."""

    source: KnowledgeSource | None = None
    source_id: str = ""
    parent_record_id: str = ""
    chunk_id: str = ""
    dataset_location: str = ""
    retrieval_methods: tuple[str, ...] = ()
    matched_terms: tuple[str, ...] = ()
    matched_entities: tuple[str, ...] = ()
    graph_paths: tuple[tuple[GraphTrace, ...], ...] = ()
    hops: int | None = None
    origin: str = ""

    @property
    def is_retrieved(self) -> bool:
        """Return whether this item came from the retrieval layer."""
        return bool(self.chunk_id)

    @property
    def has_graph_path(self) -> bool:
        """Return whether traversal contributed to this item."""
        return bool(self.graph_paths)

    def as_mapping(self) -> Mapping[str, str]:
        """Return the provenance flattened for reporting."""
        return MappingProxyType(
            {
                "source": self.source.value if self.source is not None else "",
                "source_id": self.source_id,
                "parent_record_id": self.parent_record_id,
                "chunk_id": self.chunk_id,
                "dataset_location": self.dataset_location,
                "retrieval_methods": ",".join(self.retrieval_methods),
                "hops": "" if self.hops is None else str(self.hops),
                "origin": self.origin,
            }
        )


@dataclass(frozen=True, slots=True)
class ContextItem:
    """One piece of evidence placed in a section."""

    item_id: str
    section: SectionName
    kind: EvidenceKind
    text: str = field(repr=False)
    source: KnowledgeSource | None = None
    source_id: str = ""
    relevance_score: float = 0.0
    evidence_status: EvidenceStatus = EvidenceStatus.NOT_APPLICABLE
    priority: EvidencePriority = EvidencePriority.UNSPECIFIED
    retrieval_rank: int = -1
    provenance: ItemProvenance = field(default_factory=ItemProvenance)
    metadata: Mapping[str, str] = field(default_factory=_empty_metadata, repr=False)
    truncated: bool = False
    original_length: int = 0

    @property
    def char_length(self) -> int:
        """Return the item's length in characters."""
        return len(self.text)

    def with_text(self, text: str, *, truncated: bool) -> ContextItem:
        """Return a copy carrying different text, recording whether it was cut."""
        return ContextItem(
            item_id=self.item_id,
            section=self.section,
            kind=self.kind,
            text=text,
            source=self.source,
            source_id=self.source_id,
            relevance_score=self.relevance_score,
            evidence_status=self.evidence_status,
            priority=self.priority,
            retrieval_rank=self.retrieval_rank,
            provenance=self.provenance,
            metadata=self.metadata,
            truncated=truncated,
            original_length=self.original_length or len(self.text),
        )

    def __str__(self) -> str:
        """Return the item rendered for a report line."""
        mark = " [truncated]" if self.truncated else ""
        return f"{self.item_id} ({self.kind.value}, {self.evidence_status.value}){mark}"


@dataclass(frozen=True, slots=True)
class ContextSection:
    """A named group of items."""

    name: SectionName
    items: tuple[ContextItem, ...] = ()
    truncated: bool = False

    def __len__(self) -> int:
        """Return how many items the section holds."""
        return len(self.items)

    def __iter__(self) -> Iterator[ContextItem]:
        """Iterate the items in their fixed order."""
        return iter(self.items)

    @property
    def character_count(self) -> int:
        """Return the total characters the section's items hold."""
        return sum(item.char_length for item in self.items)

    @property
    def is_empty(self) -> bool:
        """Return whether the section holds nothing."""
        return not self.items

    def with_items(self, items: Sequence[ContextItem], *, truncated: bool) -> ContextSection:
        """Return a copy holding different items."""
        return ContextSection(
            name=self.name,
            items=tuple(items),
            truncated=truncated or self.truncated,
        )


@dataclass(frozen=True, slots=True)
class ContextBudget:
    """The size limits a package must respect."""

    max_total_chars: int = 60000
    max_section_chars: int = 20000
    reserved_output_chars: int = 8000
    policy: TruncationPolicy = TruncationPolicy.TRIM_TAIL

    @property
    def available_chars(self) -> int:
        """Return the characters available to context after the output reserve."""
        return max(self.max_total_chars - self.reserved_output_chars, 0)

    def __post_init__(self) -> None:
        """Reject a budget that cannot describe a usable package."""
        if self.max_total_chars < 0 or self.max_section_chars < 0:
            raise ValueError("budget limits must not be negative")
        if self.reserved_output_chars < 0:
            raise ValueError("reserved output must not be negative")


@dataclass(frozen=True, slots=True)
class ContextWarning:
    """Something the caller should know about how the package was built."""

    code: WarningCode
    detail: str
    item_id: str = ""
    section: SectionName | None = None

    def __str__(self) -> str:
        """Return the warning rendered for a report line."""
        where = f" [{self.item_id}]" if self.item_id else ""
        return f"{self.code.value}{where}: {self.detail}"


@dataclass(frozen=True, slots=True)
class RuleContext:
    """The rule under consideration, as the caller supplied it."""

    title: str = ""
    identifier: str = ""
    rule_format: str = ""
    language: str = ""
    query: str = ""
    condition: str = ""
    log_source: str = ""
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    raw_text: str = field(default="", repr=False)

    @property
    def is_empty(self) -> bool:
        """Return whether no rule information was supplied."""
        return not any((self.title, self.identifier, self.query, self.raw_text))


@dataclass(frozen=True, slots=True)
class PackageProvenance:
    """Where the package's inputs came from."""

    operation: ContextOperation
    retrieval_mode: str = ""
    retrieval_query: str = ""
    retrieval_items: int = 0
    retrieval_candidates: int = 0
    sources_present: tuple[KnowledgeSource, ...] = ()
    unresolved_identifiers: tuple[str, ...] = ()
    ambiguous_identifiers: tuple[str, ...] = ()
    entity_count: int = 0
    mapped_count: int = 0

    def as_mapping(self) -> Mapping[str, str]:
        """Return the provenance flattened for reporting."""
        return MappingProxyType(
            {
                "operation": self.operation.value,
                "retrieval_mode": self.retrieval_mode,
                "retrieval_items": str(self.retrieval_items),
                "retrieval_candidates": str(self.retrieval_candidates),
                "sources_present": ",".join(item.value for item in self.sources_present),
                "unresolved_identifiers": ",".join(self.unresolved_identifiers),
                "ambiguous_identifiers": ",".join(self.ambiguous_identifiers),
                "entity_count": str(self.entity_count),
                "mapped_count": str(self.mapped_count),
            }
        )


@dataclass(frozen=True, slots=True)
class ContextPackage:
    """The auditable evidence package handed to Stage-15."""

    operation: ContextOperation
    rule_context: RuleContext = field(default_factory=RuleContext)
    sections: tuple[ContextSection, ...] = ()
    budget: ContextBudget = field(default_factory=ContextBudget)
    warnings: tuple[ContextWarning, ...] = ()
    provenance: PackageProvenance | None = None

    def __iter__(self) -> Iterator[ContextSection]:
        """Iterate the sections in their fixed order."""
        return iter(self.sections)

    @property
    def total_characters(self) -> int:
        """Return the characters every section's items hold together.

        Includes the warnings and metadata sections, so this is the true size of
        the package. Compare against :attr:`evidence_characters` when checking
        the budget — see that property for why the two differ.
        """
        return sum(section.character_count for section in self.sections)

    @property
    def evidence_characters(self) -> int:
        """Return the characters the budgeted sections hold.

        The warnings and metadata sections are built after budgeting and are
        deliberately exempt from it: they describe the package, including what
        was cut from it. Budgeting them would let a package drop its own
        truncation warnings to save room, which is the one thing a caller must
        never have hidden. The budget therefore governs evidence, and this is
        the figure it governs.
        """
        return sum(
            section.character_count
            for section in self.sections
            if section.name not in _REPORT_SECTIONS
        )

    @property
    def truncated(self) -> bool:
        """Return whether anything was reduced to fit the budget."""
        return any(section.truncated for section in self.sections)

    @property
    def items(self) -> tuple[ContextItem, ...]:
        """Return every item, section by section, in order."""
        return tuple(item for section in self.sections for item in section.items)

    def section(self, name: SectionName) -> ContextSection | None:
        """Return one section by name."""
        for candidate in self.sections:
            if candidate.name is name:
                return candidate
        return None

    def section_texts(self) -> Mapping[str, str]:
        """Return each section's items joined into one block.

        Offered so a later stage can map sections onto prompt variables without
        reaching into the item structure. This performs no rendering and knows
        nothing about any template.
        """
        blocks: dict[str, str] = {}
        for name in SECTION_ORDER:
            section = self.section(name)
            if section is None or section.is_empty:
                continue
            blocks[name.value] = "\n\n".join(item.text for item in section.items)
        return MappingProxyType(blocks)

    @property
    def unresolved_items(self) -> tuple[ContextItem, ...]:
        """Return every item carrying an unresolved identifier."""
        return tuple(
            item for item in self.items if item.evidence_status is EvidenceStatus.UNRESOLVED
        )

    @property
    def ambiguous_items(self) -> tuple[ContextItem, ...]:
        """Return every item carrying an ambiguous identifier."""
        return tuple(
            item for item in self.items if item.evidence_status is EvidenceStatus.AMBIGUOUS
        )
