"""File extraction.

Extracts filesystem objects: paths, names, directories and hashes.

Hashes are also recognised by shape. A 32, 40 or 64 character hex string is
unambiguous enough to extract wherever it appears, which matters for Elastic
rules whose whole query is one string. The shape says the value *is* a hash of
that length; it does not say which algorithm produced it, and no entity here
claims one.
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Final, final

from .base_extractor import FieldTable, PatternTable, route_fields, scan_shapes
from .models import Entity, ExtractionContext
from .types import EntityType

_FIELDS: Final[FieldTable] = MappingProxyType(
    {
        # Sigma / Windows
        "targetfilename": EntityType.FILE_PATH,
        "sourcefilename": EntityType.FILE_PATH,
        "filename": EntityType.FILE_NAME,
        "targetdirectory": EntityType.DIRECTORY,
        "currentdirectory": EntityType.DIRECTORY,
        "hashes": EntityType.FILE_HASH,
        "imphash": EntityType.FILE_HASH,
        "md5": EntityType.FILE_HASH,
        "sha1": EntityType.FILE_HASH,
        "sha256": EntityType.FILE_HASH,
        # ECS
        "file.path": EntityType.FILE_PATH,
        "file.target_path": EntityType.FILE_PATH,
        "file.name": EntityType.FILE_NAME,
        "file.directory": EntityType.DIRECTORY,
        "process.working_directory": EntityType.DIRECTORY,
        "file.hash.md5": EntityType.FILE_HASH,
        "file.hash.sha1": EntityType.FILE_HASH,
        "file.hash.sha256": EntityType.FILE_HASH,
        "process.hash.md5": EntityType.FILE_HASH,
        "process.hash.sha256": EntityType.FILE_HASH,
    }
)

_PATTERNS: Final[PatternTable] = MappingProxyType(
    {
        EntityType.FILE_HASH: re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b"),
    }
)


@final
class FileExtractor:
    """Extracts file paths, names, directories and hashes."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "file"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (
            EntityType.FILE_PATH,
            EntityType.FILE_NAME,
            EntityType.DIRECTORY,
            EntityType.FILE_HASH,
        )

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the filesystem objects found in the rule."""
        found = route_fields(context, _FIELDS, extractor=self.name)
        found.extend(scan_shapes(context, _PATTERNS, extractor=self.name, skip_fields=_FIELDS))
        return tuple(found)
