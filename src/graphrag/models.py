"""GraphRAG models.

Chunks, queries, scored items and the result handed to the next stage.

:class:`RetrievalResult` is the only object Stage-14 needs. It carries the
query, the mode, the ranked items with their provenance, the statistics of the
run, and the report of what the query's entities resolved to — including the
ones that resolved to nothing.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from src.knowledge.models.types import KnowledgeSource

from .provenance import ChunkProvenance, RetrievalEvidence, RetrievalProvenance, SeedReport
from .types import RetrievalMethod, RetrievalMode, SectionType


def _empty_metadata() -> Mapping[str, str]:
    """Return an immutable, empty metadata mapping."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class Chunk:
    """A bounded, addressable piece of one knowledge record."""

    chunk_id: str
    parent_record_id: str
    source: KnowledgeSource
    source_id: str
    section: SectionType
    text: str = field(repr=False)
    provenance: ChunkProvenance | None = None
    metadata: Mapping[str, str] = field(default_factory=_empty_metadata, repr=False)

    @property
    def char_length(self) -> int:
        """Return the chunk's length in characters."""
        return len(self.text)

    @property
    def token_estimate(self) -> int:
        """Return a rough token count.

        Whitespace-delimited words, not a model's tokenizer. It is a size guard,
        not a billing figure, and no tokenizer is imported to produce it.
        """
        return len(self.text.split())


@dataclass(frozen=True, slots=True)
class RetrievalQuery:
    """What the caller is asking for.

    Every field is optional except that at least one of ``text`` or
    ``entity_ids`` must carry something, so a query always states an intent.

    A field can be named twice, in two vocabularies, because the two routes ask
    different kinds of question. ``canonical_fields`` names the field the way
    the corpus documents it, which is what a graph lookup and an ECS record can
    answer to. ``lexical_fields`` names it the way the rule wrote it, which is
    what the index actually holds: the corpus's Sigma records spell the field
    ``CommandLine`` 1,366 times and ``process.command_line`` not once, so a
    lexical question asked in ECS vocabulary is asked in a vocabulary those
    records never use. Stating both lets each route ask in the vocabulary it can
    be answered in, without either translating the other.
    """

    text: str = ""
    entity_ids: tuple[str, ...] = ()
    canonical_fields: tuple[str, ...] = ()
    sources: tuple[KnowledgeSource, ...] = ()
    sections: tuple[SectionType, ...] = ()
    node_types: tuple[str, ...] = ()
    max_results: int = 10
    mode: RetrievalMode = RetrievalMode.HYBRID
    max_hops: int | None = None
    lexical_fields: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Return whether the query states nothing to look for.

        ``lexical_fields`` is not consulted. It is a second spelling of the
        fields ``canonical_fields`` already names, never a field of its own, so
        a query carrying one carries the other and asking about both here would
        only assert that twice.
        """
        return not self.text.strip() and not self.entity_ids and not self.canonical_fields

    @property
    def all_identifiers(self) -> tuple[str, ...]:
        """Return the identifiers and fields the query names, in order.

        The canonical vocabulary, and deliberately only that one. This is what
        seeds the graph and what ranking compares a candidate's entities
        against, and both need the name the corpus knows a field under: of the
        Sigma spellings, exactly one names a node at all — the ATT&CK data
        source called ``Image``, which is not the process-image field and is not
        what a rule writing ``Image`` meant. The rule's own spellings reach the
        lexical route through :attr:`lexical_vocabulary` and stop there.
        """
        return (*self.entity_ids, *self.canonical_fields)

    @property
    def lexical_vocabulary(self) -> tuple[str, ...]:
        """Return the field spellings the lexical route asks with.

        The rule's own spellings when it stated them, and the canonical ones
        otherwise. The fallback is what keeps every caller that predates this
        distinction asking exactly what it asked before, including one that
        builds a query by hand with a field list and nothing else.
        """
        return self.lexical_fields or self.canonical_fields


@dataclass(frozen=True, slots=True)
class RetrievalScore:
    """A total with the components that produced it.

    Every component is in ``[0, 1]`` and the weights sum to one, so the total is
    in ``[0, 1]`` and can be read as a proportion of the best possible match.
    """

    total: float
    exact_identifier: float = 0.0
    entity_match: float = 0.0
    lexical: float = 0.0
    graph: float = 0.0
    distance: float = 0.0
    source: float = 0.0
    section: float = 0.0

    def as_mapping(self) -> Mapping[str, float]:
        """Return the score and its components, for reporting."""
        return MappingProxyType(
            {
                "total": self.total,
                "exact_identifier": self.exact_identifier,
                "entity_match": self.entity_match,
                "lexical": self.lexical,
                "graph": self.graph,
                "distance": self.distance,
                "source": self.source,
                "section": self.section,
            }
        )


@dataclass(frozen=True, slots=True)
class RetrievalItem:
    """One retrieved chunk, its score and the account of why it is here."""

    chunk: Chunk
    score: RetrievalScore
    provenance: RetrievalProvenance

    @property
    def chunk_id(self) -> str:
        """Return the chunk's identifier."""
        return self.chunk.chunk_id

    @property
    def methods(self) -> tuple[RetrievalMethod, ...]:
        """Return the routes that found this item."""
        return self.provenance.methods

    def __str__(self) -> str:
        """Return the item rendered for a report line."""
        routes = "+".join(item.value for item in self.methods)
        return f"[{self.score.total:.3f}] {self.chunk_id} ({routes})"


@dataclass(frozen=True, slots=True)
class RetrievalStatistics:
    """What the run did."""

    text_candidates: int = 0
    graph_candidates: int = 0
    merged_candidates: int = 0
    filtered_out: int = 0
    returned: int = 0
    graph_nodes_visited: int = 0
    max_hops_used: int = 0

    def as_mapping(self) -> Mapping[str, int]:
        """Return the statistics, for reporting."""
        return MappingProxyType(
            {
                "text_candidates": self.text_candidates,
                "graph_candidates": self.graph_candidates,
                "merged_candidates": self.merged_candidates,
                "filtered_out": self.filtered_out,
                "returned": self.returned,
                "graph_nodes_visited": self.graph_nodes_visited,
                "max_hops_used": self.max_hops_used,
            }
        )


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    """The ranked, provenance-preserving answer to one query."""

    query: RetrievalQuery
    mode: RetrievalMode
    items: tuple[RetrievalItem, ...] = ()
    total_candidates: int = 0
    statistics: RetrievalStatistics = field(default_factory=RetrievalStatistics)
    seeds: tuple[SeedReport, ...] = ()

    def __len__(self) -> int:
        """Return how many items were returned."""
        return len(self.items)

    def __iter__(self) -> Iterator[RetrievalItem]:
        """Iterate the items in rank order."""
        return iter(self.items)

    @property
    def is_empty(self) -> bool:
        """Return whether nothing was retrieved."""
        return not self.items

    @property
    def unresolved_seeds(self) -> tuple[SeedReport, ...]:
        """Return the query entities that matched no node."""
        return tuple(item for item in self.seeds if item.status == "unresolved")

    @property
    def ambiguous_seeds(self) -> tuple[SeedReport, ...]:
        """Return the query entities that matched several nodes."""
        return tuple(item for item in self.seeds if item.status == "ambiguous")

    def of_source(self, source: KnowledgeSource) -> tuple[RetrievalItem, ...]:
        """Return the items from one source, in rank order."""
        return tuple(item for item in self.items if item.chunk.source is source)


@dataclass(frozen=True, slots=True)
class Candidate:
    """A chunk under consideration, with the evidence gathered so far.

    Internal to the hybrid pass. Evidence accumulates as routes report the same
    chunk; it is never merged into a single entry, so each route stays visible.
    """

    chunk: Chunk
    evidence: tuple[RetrievalEvidence, ...] = ()

    def with_evidence(self, extra: Sequence[RetrievalEvidence]) -> Candidate:
        """Return a copy carrying additional evidence."""
        return Candidate(chunk=self.chunk, evidence=(*self.evidence, *extra))
