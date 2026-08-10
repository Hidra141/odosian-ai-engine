"""JSONL-backed repository.

Answers lookups over the datasets without exposing where they live.

Records are read once per source, on first use, and held in the instance that
read them. The index is derived: it exists in memory for the life of the
repository and no part of it is written back to disk, so the datasets remain the
single source of truth. Nothing is cached at module level, so two repositories
never share state.

Iteration order is file order, always. A lookup by source id returns every match
rather than one, because nothing in the corpus guarantees source ids are unique
and returning a single record would hide a collision.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import final

from ..loader.jsonl_loader import JsonlKnowledgeLoader
from ..loader.layout import CorpusLayout
from ..models.exceptions import KnowledgeSourceUnavailableError
from ..models.records import KnowledgeRecord
from ..models.types import KnowledgeSource


@dataclass(frozen=True, slots=True)
class SourceIndex:
    """The records of one source, in file order, with lookup tables."""

    source: KnowledgeSource
    records: tuple[KnowledgeRecord, ...]
    by_id: dict[str, KnowledgeRecord]
    by_source_id: dict[str, tuple[KnowledgeRecord, ...]]

    @classmethod
    def build(
        cls,
        source: KnowledgeSource,
        records: Iterable[KnowledgeRecord],
    ) -> SourceIndex:
        """Build an index over a source's records, preserving their order."""
        ordered = tuple(records)
        by_id: dict[str, KnowledgeRecord] = {}
        grouped: dict[str, list[KnowledgeRecord]] = {}
        for record in ordered:
            by_id.setdefault(record.id, record)
            grouped.setdefault(record.source_id, []).append(record)
        return cls(
            source=source,
            records=ordered,
            by_id=by_id,
            by_source_id={key: tuple(value) for key, value in grouped.items()},
        )

    @property
    def duplicate_ids(self) -> tuple[str, ...]:
        """Return envelope ids that appear more than once, in first-seen order."""
        seen: dict[str, int] = {}
        for record in self.records:
            seen[record.id] = seen.get(record.id, 0) + 1
        return tuple(key for key, count in seen.items() if count > 1)


@final
class JsonlKnowledgeRepository:
    """Serves knowledge records from the JSONL datasets."""

    __slots__ = ("_layout", "_loader", "_indexes")

    def __init__(
        self,
        layout: CorpusLayout,
        loader: JsonlKnowledgeLoader | None = None,
    ) -> None:
        """Build a repository over one corpus root. Nothing is read yet."""
        self._layout = layout
        self._loader = loader if loader is not None else JsonlKnowledgeLoader(layout=layout)
        self._indexes: dict[KnowledgeSource, SourceIndex] = {}

    @classmethod
    def from_root(cls, root: Path) -> JsonlKnowledgeRepository:
        """Build a repository over a corpus root directory."""
        return cls(CorpusLayout(root=root))

    @property
    def root(self) -> Path:
        """Return the corpus root this repository reads from."""
        return self._layout.root

    def available_sources(self) -> tuple[KnowledgeSource, ...]:
        """Return the sources whose dataset is present."""
        return self._layout.available_sources()

    def missing_sources(self) -> tuple[KnowledgeSource, ...]:
        """Return the approved sources whose dataset is absent."""
        return self._layout.missing_sources()

    def iterate_source(self, source: KnowledgeSource) -> Iterator[KnowledgeRecord]:
        """Yield a source's records in file order."""
        return iter(self._index(source).records)

    def iterate_all(self) -> Iterator[KnowledgeRecord]:
        """Yield every available source's records, source by source."""
        for source in self.available_sources():
            yield from self.iterate_source(source)

    def count(self, source: KnowledgeSource) -> int:
        """Return how many records a source holds."""
        return len(self._index(source).records)

    def total_count(self) -> int:
        """Return how many records every available source holds together."""
        return sum(self.count(source) for source in self.available_sources())

    def get_by_id(self, source: KnowledgeSource, record_id: str) -> KnowledgeRecord | None:
        """Return the record with an envelope id, or ``None`` when absent."""
        return self._index(source).by_id.get(record_id)

    def find_by_source_id(
        self,
        source: KnowledgeSource,
        source_id: str,
    ) -> tuple[KnowledgeRecord, ...]:
        """Return every record carrying a source id, in file order."""
        return self._index(source).by_source_id.get(source_id, ())

    def duplicate_ids(self, source: KnowledgeSource) -> tuple[str, ...]:
        """Return envelope ids a source repeats, if any."""
        return self._index(source).duplicate_ids

    def is_loaded(self, source: KnowledgeSource) -> bool:
        """Return whether a source has been read yet."""
        return source in self._indexes

    def _index(self, source: KnowledgeSource) -> SourceIndex:
        """Return a source's index, reading the dataset on first use."""
        index = self._indexes.get(source)
        if index is not None:
            return index
        if not self._layout.exists(source):
            raise KnowledgeSourceUnavailableError(
                source.value,
                self._layout.path_for(source),
                "file does not exist",
            )
        built = SourceIndex.build(source, self._loader.load(source))
        self._indexes[source] = built
        return built
