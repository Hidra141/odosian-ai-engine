"""Retrieval validation.

Checks that an index and a result are internally consistent.

The checks are about integrity, not about how full the result looks. An empty
result is valid; a result whose item claims a chunk id no index holds is not.
Every issue is collected before reporting, so one run names every problem.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import final

from .exceptions import RetrievalValidationError
from .models import Chunk, RetrievalResult
from .text_index import TextIndex


@dataclass(frozen=True, slots=True)
class RetrievalIssue:
    """One problem found in an index or a result."""

    check: str
    detail: str

    def __str__(self) -> str:
        """Return the issue rendered as ``check: detail``."""
        return f"{self.check}: {self.detail}"


@dataclass(frozen=True, slots=True)
class RetrievalValidationResult:
    """The outcome of validating an index or a result."""

    issues: tuple[RetrievalIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        """Return whether everything passed."""
        return not self.issues

    def raise_if_invalid(self) -> None:
        """Raise :class:`RetrievalValidationError` when any issue was found."""
        if self.issues:
            raise RetrievalValidationError([str(item) for item in self.issues])


@final
class RetrievalValidator:
    """Checks chunks, indexes and results."""

    __slots__ = ()

    def validate_chunks(self, chunks: Sequence[Chunk], max_chars: int) -> RetrievalValidationResult:
        """Check chunk identity, provenance and size bounds."""
        return RetrievalValidationResult(
            (
                *self._duplicate_chunk_ids(chunks),
                *self._missing_chunk_provenance(chunks),
                *self._oversized(chunks, max_chars),
            )
        )

    def validate_result(
        self,
        result: RetrievalResult,
        index: TextIndex,
    ) -> RetrievalValidationResult:
        """Check that every item is traceable and every score is well formed."""
        return RetrievalValidationResult(
            (
                *self._unknown_chunks(result, index),
                *self._missing_provenance(result),
                *self._malformed_scores(result),
                *self._unordered(result),
            )
        )

    def _duplicate_chunk_ids(self, chunks: Sequence[Chunk]) -> Iterator[RetrievalIssue]:
        """Yield an issue for any chunk id used twice."""
        seen: dict[str, int] = {}
        for chunk in chunks:
            seen[chunk.chunk_id] = seen.get(chunk.chunk_id, 0) + 1
        for chunk_id, count in seen.items():
            if count > 1:
                yield RetrievalIssue("duplicate_chunk_id", f"{chunk_id} appears {count} times")

    def _missing_chunk_provenance(self, chunks: Sequence[Chunk]) -> Iterator[RetrievalIssue]:
        """Yield an issue for any chunk without provenance or a parent."""
        for chunk in chunks:
            if chunk.provenance is None:
                yield RetrievalIssue("missing_chunk_provenance", chunk.chunk_id)
            if not chunk.parent_record_id:
                yield RetrievalIssue("missing_parent_record", chunk.chunk_id)
            elif not chunk.chunk_id.startswith(chunk.parent_record_id):
                yield RetrievalIssue(
                    "invalid_parent_id",
                    f"{chunk.chunk_id} does not derive from {chunk.parent_record_id}",
                )

    def _oversized(self, chunks: Sequence[Chunk], max_chars: int) -> Iterator[RetrievalIssue]:
        """Yield an issue for any chunk beyond the configured bound."""
        for chunk in chunks:
            if chunk.char_length > max_chars:
                yield RetrievalIssue(
                    "chunk_over_bound",
                    f"{chunk.chunk_id} is {chunk.char_length} chars (limit {max_chars})",
                )

    def _unknown_chunks(
        self,
        result: RetrievalResult,
        index: TextIndex,
    ) -> Iterator[RetrievalIssue]:
        """Yield an issue for any item the index does not hold."""
        for item in result.items:
            if index.chunk(item.chunk_id) is None:
                yield RetrievalIssue("unknown_chunk", item.chunk_id)

    def _missing_provenance(self, result: RetrievalResult) -> Iterator[RetrievalIssue]:
        """Yield an issue for any item that cannot explain itself."""
        for item in result.items:
            provenance = item.provenance
            if not provenance.methods:
                yield RetrievalIssue("no_retrieval_method", item.chunk_id)
            if not provenance.evidence:
                yield RetrievalIssue("no_evidence", item.chunk_id)
            if not provenance.source_id or not provenance.parent_record_id:
                yield RetrievalIssue("incomplete_provenance", item.chunk_id)

    def _malformed_scores(self, result: RetrievalResult) -> Iterator[RetrievalIssue]:
        """Yield an issue for any score outside the unit interval."""
        for item in result.items:
            if not 0.0 <= item.score.total <= 1.0:
                yield RetrievalIssue(
                    "score_out_of_range", f"{item.chunk_id} scored {item.score.total}"
                )

    def _unordered(self, result: RetrievalResult) -> Iterator[RetrievalIssue]:
        """Yield an issue when items are not in descending score order."""
        totals = [item.score.total for item in result.items]
        if totals != sorted(totals, reverse=True):
            yield RetrievalIssue("unordered_items", "items are not in descending score order")
