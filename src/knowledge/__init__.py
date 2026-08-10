"""Knowledge base.

Software layer that loads, normalises and retrieves knowledge records.

The layer serves five JSONL datasets — MITRE, Sigma, Elastic, LOLBAS and ECS —
through one abstraction, without exposing where they live. The datasets are
immutable inputs: nothing here opens a file for writing, and no derived index is
persisted.

It reads and reports. It does not repair. A malformed line stops the load rather
than being skipped, a reference with no target is reported unresolved rather
than substituted, and a field a source does not carry is named as unknown rather
than filled in. The known defects in the corpus — ATT&CK version skew, records
without relationships, two malformed Elastic identifiers, differing field names
between sources — surface as explicit status, never as silent repair.

Typical use::

    repository = JsonlKnowledgeRepository.from_root(knowledge_root)
    resolver = DefaultKnowledgeResolver(repository)
    result = resolver.resolve(reference)
    if result.is_resolved:
        record = result.record
"""

from __future__ import annotations

from .interfaces.protocols import (
    KnowledgeLoader,
    KnowledgeNormalizer,
    KnowledgeRepository,
    KnowledgeResolver,
)
from .loader.jsonl_loader import ENVELOPE_KEYS, JsonlKnowledgeLoader
from .loader.layout import CorpusLayout
from .models.exceptions import (
    InvalidRecordError,
    KnowledgeError,
    KnowledgeSourceUnavailableError,
    RecordDecodeError,
    UnknownKnowledgeSourceError,
)
from .models.records import (
    KnowledgeRecord,
    KnowledgeReference,
    NormalizedKnowledgeRecord,
    RecordProvenance,
    ResolutionReport,
    ResolutionResult,
)
from .models.types import KnowledgeSource, ReferenceKind, ResolutionStatus
from .normalizer.record_normalizer import DefaultKnowledgeNormalizer
from .normalizer.references import canonical_identifier, classify_identifier, references_of
from .repository.jsonl_repository import JsonlKnowledgeRepository, SourceIndex
from .resolver.reference_resolver import KIND_SOURCES, DefaultKnowledgeResolver

__all__ = [
    "ENVELOPE_KEYS",
    "KIND_SOURCES",
    "CorpusLayout",
    "DefaultKnowledgeNormalizer",
    "DefaultKnowledgeResolver",
    "InvalidRecordError",
    "JsonlKnowledgeLoader",
    "JsonlKnowledgeRepository",
    "KnowledgeError",
    "KnowledgeLoader",
    "KnowledgeNormalizer",
    "KnowledgeRecord",
    "KnowledgeReference",
    "KnowledgeRepository",
    "KnowledgeResolver",
    "KnowledgeSource",
    "KnowledgeSourceUnavailableError",
    "NormalizedKnowledgeRecord",
    "RecordDecodeError",
    "RecordProvenance",
    "ReferenceKind",
    "ResolutionReport",
    "ResolutionResult",
    "ResolutionStatus",
    "SourceIndex",
    "UnknownKnowledgeSourceError",
    "canonical_identifier",
    "classify_identifier",
    "references_of",
]
