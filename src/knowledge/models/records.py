"""Knowledge records.

The models every source is represented by, and the results of normalising and
resolving them.

A :class:`KnowledgeRecord` holds the envelope exactly as the dataset wrote it,
including ``metadata`` in its decoded form. Metadata is *not* flattened into a
shared schema: MITRE's ``techniqueId``, Sigma's ``mitreTechniques`` and LOLBAS's
``mitreTechnique`` stay where and as they are, because a universal schema would
have to invent the fields a source does not have.

:class:`NormalizedKnowledgeRecord` adds a cross-source view *beside* the record
rather than in place of it. Anything that could not be derived deterministically
is named in :attr:`NormalizedKnowledgeRecord.unknown_fields` instead of being
filled in.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from .types import KnowledgeSource, RawMetadata, ReferenceKind, ResolutionStatus


def _empty_metadata() -> RawMetadata:
    """Return an immutable, empty metadata mapping."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class RecordProvenance:
    """Where a record came from."""

    source: KnowledgeSource
    path: Path
    line_number: int

    def __str__(self) -> str:
        """Return the provenance rendered as ``source:path:line``."""
        return f"{self.source.value}:{self.path.name}:{self.line_number}"


@dataclass(frozen=True, slots=True)
class KnowledgeRecord:
    """One record from one dataset, as the dataset wrote it."""

    source: KnowledgeSource
    id: str
    source_id: str
    text: str
    metadata: RawMetadata = field(default_factory=_empty_metadata, repr=False)
    provenance: RecordProvenance | None = None

    def metadata_value(self, key: str) -> object:
        """Return a raw metadata value, or ``None`` when the key is absent."""
        return self.metadata.get(key)

    def metadata_str(self, key: str) -> str | None:
        """Return a metadata value when it is a non-empty string."""
        value = self.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value
        return None


@dataclass(frozen=True, slots=True)
class KnowledgeReference:
    """A pointer from one record to something that may exist in the corpus."""

    kind: ReferenceKind
    value: str
    origin_source: KnowledgeSource | None = None
    origin_record_id: str | None = None
    origin_field: str = ""

    def __str__(self) -> str:
        """Return the reference rendered as ``kind:value``."""
        return f"{self.kind.value}:{self.value}"


@dataclass(frozen=True, slots=True)
class NormalizedKnowledgeRecord:
    """A cross-source view of a record, carrying the original alongside."""

    record: KnowledgeRecord
    canonical_id: str
    identifiers: tuple[str, ...] = ()
    title: str | None = None
    url: str | None = None
    object_type: str | None = None
    references: tuple[KnowledgeReference, ...] = ()
    unknown_fields: tuple[str, ...] = ()

    @property
    def source(self) -> KnowledgeSource:
        """Return the source the underlying record came from."""
        return self.record.source

    @property
    def provenance(self) -> RecordProvenance | None:
        """Return the provenance of the underlying record."""
        return self.record.provenance

    @property
    def is_fully_normalized(self) -> bool:
        """Return whether every cross-source field could be derived."""
        return not self.unknown_fields


@dataclass(frozen=True, slots=True)
class ResolutionResult:
    """The outcome of resolving one reference against the corpus."""

    reference: KnowledgeReference
    status: ResolutionStatus
    records: tuple[KnowledgeRecord, ...] = ()
    note: str = ""

    @property
    def record(self) -> KnowledgeRecord | None:
        """Return the single target, or ``None`` unless exactly one was found."""
        return self.records[0] if self.status is ResolutionStatus.RESOLVED else None

    @property
    def is_resolved(self) -> bool:
        """Return whether a single target was established."""
        return self.status.is_resolved

    def __str__(self) -> str:
        """Return the result rendered for a report line."""
        return f"{self.reference} -> {self.status.value} ({len(self.records)} candidates)"


@dataclass(frozen=True, slots=True)
class ResolutionReport:
    """Every resolution attempt made for one batch of references."""

    results: tuple[ResolutionResult, ...] = ()

    def __len__(self) -> int:
        """Return how many references were attempted."""
        return len(self.results)

    def __iter__(self) -> Iterator[ResolutionResult]:
        """Iterate the results in the order the references were given."""
        return iter(self.results)

    def of_status(self, status: ResolutionStatus) -> tuple[ResolutionResult, ...]:
        """Return the results with one status, in order."""
        return tuple(item for item in self.results if item.status is status)

    @property
    def counts(self) -> Mapping[ResolutionStatus, int]:
        """Return how many results reached each status."""
        tally: dict[ResolutionStatus, int] = {status: 0 for status in ResolutionStatus}
        for item in self.results:
            tally[item.status] += 1
        return MappingProxyType(tally)
