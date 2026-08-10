"""Corpus layout.

Maps a source onto the file that holds it.

The root directory is supplied by the caller; nothing here hardcodes a path. The
layout below the root is the corpus convention — ``<root>/<source>/<source>.jsonl``
— and is the single place that convention is written down.

This module reads directory entries to answer availability. It never writes,
creates or removes anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..models.types import KnowledgeSource

DATASET_SUFFIX: Final[str] = ".jsonl"


@dataclass(frozen=True, slots=True)
class CorpusLayout:
    """Where each source's dataset lives beneath one root directory."""

    root: Path

    def path_for(self, source: KnowledgeSource) -> Path:
        """Return the dataset path of a source, whether or not it exists."""
        return self.root / source.value / f"{source.value}{DATASET_SUFFIX}"

    def exists(self, source: KnowledgeSource) -> bool:
        """Return whether a source's dataset is present and is a file."""
        return self.path_for(source).is_file()

    def available_sources(self) -> tuple[KnowledgeSource, ...]:
        """Return the sources whose dataset is present, in declaration order."""
        return tuple(source for source in KnowledgeSource if self.exists(source))

    def missing_sources(self) -> tuple[KnowledgeSource, ...]:
        """Return the sources whose dataset is absent, in declaration order."""
        return tuple(source for source in KnowledgeSource if not self.exists(source))
