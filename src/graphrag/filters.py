"""Filters.

Deterministic narrowing applied before ranking.

Filters test what a chunk states. A chunk whose record does not carry a
platform is not excluded by a platform filter unless the filter is asked for —
absence is never treated as a mismatch, and no value is inferred to make a
filter succeed.

Filtering happens before ranking so that a narrowed query spends its result
budget on candidates the caller can actually use.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import final

from src.knowledge.models.types import KnowledgeSource

from .models import Candidate, Chunk, RetrievalQuery
from .types import SectionType


def query_predicate(query: RetrievalQuery) -> Callable[[Chunk], bool] | None:
    """Return a chunk test for a query's filters, or ``None`` when it has none.

    Candidate generation applies this while walking its ranked list, so a
    narrowed query spends its budget on chunks it can actually use. Filtering
    only after generation would let a broad match crowd out every chunk the
    filter wanted: the corpus holds 413 detection chunks against 7,458 summary
    ones, so a section filter applied late returns almost nothing.
    """
    if not query.sources and not query.sections:
        return None
    sources = set(query.sources)
    sections = set(query.sections)

    def admits(chunk: Chunk) -> bool:
        if sources and chunk.source not in sources:
            return False
        return not (sections and chunk.section not in sections)

    return admits


@dataclass(frozen=True, slots=True)
class FilterOutcome:
    """What a filter pass kept and what it removed."""

    kept: tuple[Candidate, ...] = ()
    removed: int = 0


@final
@dataclass(frozen=True, slots=True)
class CandidateFilter:
    """Applies a query's filters to a candidate set."""

    def apply(self, candidates: Sequence[Candidate], query: RetrievalQuery) -> FilterOutcome:
        """Return the candidates a query's filters admit, in the order given."""
        kept = [item for item in candidates if self._admits(item, query)]
        return FilterOutcome(tuple(kept), len(candidates) - len(kept))

    def _admits(self, candidate: Candidate, query: RetrievalQuery) -> bool:
        """Return whether one candidate passes every filter the query states."""
        chunk = candidate.chunk
        if query.sources and chunk.source not in query.sources:
            return False
        if query.sections and chunk.section not in query.sections:
            return False
        return True


def by_source(
    candidates: Sequence[Candidate],
    sources: Sequence[KnowledgeSource],
) -> tuple[Candidate, ...]:
    """Return the candidates from a set of sources, in the order given."""
    if not sources:
        return tuple(candidates)
    wanted = set(sources)
    return tuple(item for item in candidates if item.chunk.source in wanted)


def by_section(
    candidates: Sequence[Candidate],
    sections: Sequence[SectionType],
) -> tuple[Candidate, ...]:
    """Return the candidates from a set of sections, in the order given."""
    if not sections:
        return tuple(candidates)
    wanted = set(sections)
    return tuple(item for item in candidates if item.chunk.section in wanted)
