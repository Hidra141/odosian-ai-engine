"""JSONL loading.

Reads a dataset one line at a time and yields records.

Reading is a generator over the file handle, so the caller controls how much is
held at once and no assumption is made about record size. The corpus contains a
Sigma record of roughly a quarter of a megabyte on a single line; nothing here
buffers by a fixed width or truncates.

A line that will not decode, or that decodes to something without the expected
envelope, raises. It is never skipped and never repaired: a corpus that is
quietly missing records is worse than one that refuses to load, because the gap
becomes invisible to everything downstream.

The file is opened for reading only. Nothing in this module writes.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final, final

from ..models.exceptions import (
    InvalidRecordError,
    KnowledgeSourceUnavailableError,
    RecordDecodeError,
)
from ..models.records import KnowledgeRecord, RecordProvenance
from ..models.types import KnowledgeSource
from .layout import CorpusLayout

ENVELOPE_KEYS: Final[tuple[str, ...]] = ("id", "sourceId", "text", "metadata")


@final
@dataclass(frozen=True, slots=True)
class JsonlKnowledgeLoader:
    """Loads knowledge records from the JSONL datasets."""

    layout: CorpusLayout
    encoding: str = "utf-8"

    def available_sources(self) -> tuple[KnowledgeSource, ...]:
        """Return the sources whose dataset can be read."""
        return self.layout.available_sources()

    def load(self, source: KnowledgeSource) -> Iterator[KnowledgeRecord]:
        """Yield a source's records in file order."""
        return self.load_path(source, self.layout.path_for(source))

    def load_path(self, source: KnowledgeSource, path: Path) -> Iterator[KnowledgeRecord]:
        """Yield the records of one dataset file in file order."""
        if not path.is_file():
            raise KnowledgeSourceUnavailableError(source.value, path, "file does not exist")
        try:
            handle = path.open(encoding=self.encoding)
        except OSError as error:
            raise KnowledgeSourceUnavailableError(source.value, path, str(error)) from error
        with handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                yield self._build(source, path, line_number, line)

    def _build(
        self,
        source: KnowledgeSource,
        path: Path,
        line_number: int,
        line: str,
    ) -> KnowledgeRecord:
        """Decode one line and check its envelope."""
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as error:
            raise RecordDecodeError(source.value, path, line_number, error.msg) from error

        if not isinstance(decoded, dict):
            raise InvalidRecordError(
                source.value,
                path,
                line_number,
                f"expected a JSON object, got {type(decoded).__name__}",
            )

        for key in ENVELOPE_KEYS:
            if key not in decoded:
                raise InvalidRecordError(
                    source.value, path, line_number, f"missing envelope key {key!r}"
                )

        record_id = decoded["id"]
        source_id = decoded["sourceId"]
        text = decoded["text"]
        metadata = decoded["metadata"]

        for key, value, expected in (
            ("id", record_id, str),
            ("sourceId", source_id, str),
            ("text", text, str),
        ):
            if not isinstance(value, expected):
                raise InvalidRecordError(
                    source.value,
                    path,
                    line_number,
                    f"envelope key {key!r} must be a string, got {type(value).__name__}",
                )
        if not isinstance(metadata, dict):
            raise InvalidRecordError(
                source.value,
                path,
                line_number,
                f"envelope key 'metadata' must be an object, got {type(metadata).__name__}",
            )

        return KnowledgeRecord(
            source=source,
            id=record_id,
            source_id=source_id,
            text=text,
            metadata=MappingProxyType(dict(metadata)),
            provenance=RecordProvenance(source=source, path=path, line_number=line_number),
        )
