"""Text index.

A derived lexical index over the chunks, built outside the raw corpus.

Retrieval is BM25 over a deterministic tokenizer. That choice is deliberate: it
needs no embedding service, no vector store and no network, so the whole layer
can be built and verified offline, and it produces the same ranking for the same
input every time. A future embedding retriever fits behind the same interface
without changing anything that uses it.

The tokenizer keeps dotted identifiers whole and *also* emits their parts, so
``process.command_line`` matches a query for ``process.command_line``,
``process`` or ``command_line``, and ``T1059.001`` matches ``T1059`` too. That
is what lets an exact ATT&CK identifier find its records without a special case.

The index is rebuildable from the corpus and never written into it. Persistence
is optional and refuses any path inside the knowledge directory.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, final

from .config import GraphRagSettings
from .exceptions import IndexPersistenceError
from .models import Chunk

_TOKEN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9]+(?:[._\-][A-Za-z0-9]+)*")
_PROTECTED_DIR: Final[str] = "resources/knowledge"
INDEX_FORMAT_VERSION: Final[int] = 1


def tokenize(text: str) -> list[str]:
    """Return the search tokens of a string, deterministically.

    A dotted or hyphenated identifier yields itself and each of its parts, so an
    identifier can be found whole or by any component.
    """
    tokens: list[str] = []
    for match in _TOKEN.finditer(text.lower()):
        whole = match.group(0)
        tokens.append(whole)
        if any(sep in whole for sep in "._-"):
            tokens.extend(part for part in re.split(r"[._\-]", whole) if part)
    return tokens


@dataclass(frozen=True, slots=True)
class IndexStatistics:
    """What an index holds."""

    chunks: int = 0
    terms: int = 0
    postings: int = 0
    total_tokens: int = 0
    average_length: float = 0.0
    per_source: Mapping[str, int] = field(default_factory=dict)


@final
class TextIndex:
    """A BM25 index over chunks."""

    __slots__ = (
        "_settings",
        "_chunks",
        "_order",
        "_postings",
        "_lengths",
        "_by_record",
        "_average",
        "_built",
    )

    def __init__(self, settings: GraphRagSettings) -> None:
        """Build an empty index."""
        self._settings = settings
        self._chunks: dict[str, Chunk] = {}
        self._order: list[str] = []
        self._postings: dict[str, dict[str, int]] = {}
        self._lengths: dict[str, int] = {}
        self._by_record: dict[str, tuple[Chunk, ...]] = {}
        self._average = 0.0
        self._built = False

    @property
    def is_built(self) -> bool:
        """Return whether the index holds anything."""
        return self._built

    @property
    def chunk_ids(self) -> tuple[str, ...]:
        """Return every indexed chunk id, in insertion order."""
        return tuple(self._order)

    def chunk(self, chunk_id: str) -> Chunk | None:
        """Return an indexed chunk by id."""
        return self._chunks.get(chunk_id)

    def chunks_of_record(self, parent_record_id: str) -> tuple[Chunk, ...]:
        """Return every chunk of one record, in document order.

        Answered from an index built alongside the postings. Graph retrieval
        calls this once per reached node, so a scan of every chunk here would
        make traversal cost grow with the whole corpus.
        """
        return self._by_record.get(parent_record_id, ())

    def build(self, chunks: Iterable[Chunk]) -> IndexStatistics:
        """Index a set of chunks, replacing anything already held."""
        self._chunks.clear()
        self._order.clear()
        self._postings.clear()
        self._lengths.clear()
        self._by_record.clear()
        grouped: dict[str, list[Chunk]] = {}
        per_source: Counter[str] = Counter()
        total_tokens = 0

        for chunk in chunks:
            if chunk.chunk_id in self._chunks:
                continue
            self._chunks[chunk.chunk_id] = chunk
            self._order.append(chunk.chunk_id)
            grouped.setdefault(chunk.parent_record_id, []).append(chunk)
            per_source[chunk.source.value] += 1
            counts = Counter(tokenize(chunk.text))
            self._lengths[chunk.chunk_id] = sum(counts.values())
            total_tokens += self._lengths[chunk.chunk_id]
            for term, count in counts.items():
                self._postings.setdefault(term, {})[chunk.chunk_id] = count

        self._by_record = {key: tuple(value) for key, value in grouped.items()}
        size = len(self._order)
        self._average = (total_tokens / size) if size else 0.0
        self._built = True
        return IndexStatistics(
            chunks=size,
            terms=len(self._postings),
            postings=sum(len(item) for item in self._postings.values()),
            total_tokens=total_tokens,
            average_length=self._average,
            per_source=dict(sorted(per_source.items())),
        )

    def search(
        self,
        query: str,
        limit: int,
        predicate: Callable[[Chunk], bool] | None = None,
    ) -> list[tuple[str, float, tuple[str, ...]]]:
        """Return ``(chunk_id, score, matched terms)`` for a query, best first.

        ``predicate`` is applied while walking the ranked list, so ``limit``
        counts chunks that passed it rather than chunks that were then thrown
        away. Ties are broken by chunk id so the order is stable across runs.
        """
        terms = tokenize(query)
        if not terms or not self._built:
            return []
        total = len(self._order)
        scores: dict[str, float] = {}
        matched: dict[str, set[str]] = {}
        k1 = self._settings.bm25_k1
        b = self._settings.bm25_b

        for term in dict.fromkeys(terms):
            postings = self._postings.get(term)
            if not postings:
                continue
            idf = math.log(1.0 + (total - len(postings) + 0.5) / (len(postings) + 0.5))
            for chunk_id, frequency in postings.items():
                length = self._lengths[chunk_id] or 1
                denominator = frequency + k1 * (1 - b + b * length / (self._average or 1.0))
                scores[chunk_id] = scores.get(chunk_id, 0.0) + idf * (frequency * (k1 + 1)) / denominator
                matched.setdefault(chunk_id, set()).add(term)

        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        admitted: list[tuple[str, float, tuple[str, ...]]] = []
        for chunk_id, score in ranked:
            if predicate is not None and not predicate(self._chunks[chunk_id]):
                continue
            admitted.append((chunk_id, score, tuple(sorted(matched[chunk_id]))))
            if len(admitted) >= limit:
                break
        return admitted

    def save(self, path: Path) -> None:
        """Persist the index outside the raw corpus.

        Refuses any path inside the knowledge directory, so a derived artefact
        can never be mistaken for source data or overwrite it.
        """
        _reject_protected(path)
        payload = {
            "format": INDEX_FORMAT_VERSION,
            "order": self._order,
            "lengths": self._lengths,
            "average": self._average,
            "postings": self._postings,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError as error:
            raise IndexPersistenceError(path, str(error)) from error

    def statistics(self) -> IndexStatistics:
        """Return the current index statistics."""
        per_source: Counter[str] = Counter(
            self._chunks[key].source.value for key in self._order
        )
        return IndexStatistics(
            chunks=len(self._order),
            terms=len(self._postings),
            postings=sum(len(item) for item in self._postings.values()),
            total_tokens=sum(self._lengths.values()),
            average_length=self._average,
            per_source=dict(sorted(per_source.items())),
        )


def _reject_protected(path: Path) -> None:
    """Raise when a path points inside the immutable knowledge directory."""
    normalized = str(path.resolve()).replace("\\", "/").lower()
    if _PROTECTED_DIR in normalized:
        raise IndexPersistenceError(path, "derived data must not live inside the raw corpus")


def chunk_sort_key(chunk: Chunk) -> tuple[str, str]:
    """Return a stable ordering key for a chunk."""
    return (chunk.parent_record_id, chunk.chunk_id)


def dedupe_chunks(chunks: Sequence[Chunk]) -> tuple[Chunk, ...]:
    """Return chunks with duplicate ids removed, first occurrence winning."""
    seen: dict[str, Chunk] = {}
    for chunk in chunks:
        seen.setdefault(chunk.chunk_id, chunk)
    return tuple(seen.values())
