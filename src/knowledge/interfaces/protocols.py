"""Knowledge contracts.

The four roles the knowledge layer is built from, expressed as protocols so an
implementation conforms by shape rather than by inheritance.

None of these mention a file, a path, a database or a model. A caller depends on
what the layer does, not on the fact that the MVP answers it from JSONL, so
replacing the storage later changes no downstream code.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Protocol, runtime_checkable

from ..models.records import (
    KnowledgeRecord,
    KnowledgeReference,
    NormalizedKnowledgeRecord,
    ResolutionReport,
    ResolutionResult,
)
from ..models.types import KnowledgeSource


@runtime_checkable
class KnowledgeLoader(Protocol):
    """Reads the records of one source."""

    def load(self, source: KnowledgeSource) -> Iterator[KnowledgeRecord]:
        """Yield the records of a source in file order.

        Streams: a caller may consume records without the whole dataset being
        held in memory. A record that cannot be decoded or does not carry the
        expected envelope raises rather than being skipped.
        """
        ...

    def available_sources(self) -> tuple[KnowledgeSource, ...]:
        """Return the sources whose dataset can be read."""
        ...


@runtime_checkable
class KnowledgeRepository(Protocol):
    """Answers questions about records without exposing where they are stored."""

    def available_sources(self) -> tuple[KnowledgeSource, ...]:
        """Return the sources this repository can serve."""
        ...

    def iterate_source(self, source: KnowledgeSource) -> Iterator[KnowledgeRecord]:
        """Yield a source's records in a deterministic order."""
        ...

    def count(self, source: KnowledgeSource) -> int:
        """Return how many records a source holds."""
        ...

    def get_by_id(self, source: KnowledgeSource, record_id: str) -> KnowledgeRecord | None:
        """Return the record with an envelope id, or ``None``."""
        ...

    def find_by_source_id(
        self,
        source: KnowledgeSource,
        source_id: str,
    ) -> tuple[KnowledgeRecord, ...]:
        """Return every record carrying a source id, in file order.

        Returns a sequence rather than one record because nothing guarantees a
        source id is unique, and collapsing duplicates would hide that.
        """
        ...


@runtime_checkable
class KnowledgeNormalizer(Protocol):
    """Derives a cross-source view of a record without altering it."""

    def normalize(self, record: KnowledgeRecord) -> NormalizedKnowledgeRecord:
        """Return the normalized view of one record.

        The record is carried through untouched. A field that cannot be derived
        deterministically is named as unknown rather than filled in.
        """
        ...

    def references_of(self, record: KnowledgeRecord) -> tuple[KnowledgeReference, ...]:
        """Return the references a record states, in the order it states them."""
        ...


@runtime_checkable
class KnowledgeResolver(Protocol):
    """Resolves references against the records a repository holds."""

    def resolve(self, reference: KnowledgeReference) -> ResolutionResult:
        """Return what a reference points at, if anything.

        Never invents a target. A reference with no match is reported as
        unresolved, and one with several is reported as ambiguous.
        """
        ...

    def resolve_all(self, references: Iterable[KnowledgeReference]) -> ResolutionReport:
        """Resolve several references, preserving their order."""
        ...

    def resolve_record(self, record: KnowledgeRecord) -> ResolutionReport:
        """Resolve every reference one record states."""
        ...

    def supported_kinds(self) -> Sequence[str]:
        """Return the reference kinds this resolver knows how to look up."""
        ...
