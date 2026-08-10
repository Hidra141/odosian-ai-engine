"""Reference resolution.

Looks a reference up against the records the repository holds, and reports what
was found — one record, none, or several.

Each reference kind is looked up in the sources that can answer it, and only
there. An ATT&CK technique is sought in MITRE; an ECS field in ECS; a Sigma rule
in Sigma. The routing table is written out rather than derived, so a reader can
see exactly which corpus answers which question.

**Nothing is ever substituted.** If a rule cites ``T1562`` and the loaded MITRE
corpus does not contain it, the result is unresolved. It is not replaced by a
successor identifier, a parent technique, a near match, or anything the prose
might suggest. The version skew between the rule corpora and the MITRE snapshot
is a fact about the data, and reporting it as unresolved is how that fact
survives into later stages.

An identifier claimed by more than one record is reported as ambiguous with
every candidate attached. None is chosen.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final, final

from ..models.records import (
    KnowledgeRecord,
    KnowledgeReference,
    ResolutionReport,
    ResolutionResult,
)
from ..models.types import KnowledgeSource, ReferenceKind, ResolutionStatus
from ..normalizer.record_normalizer import DefaultKnowledgeNormalizer
from ..repository.jsonl_repository import JsonlKnowledgeRepository

KIND_SOURCES: Final[dict[ReferenceKind, tuple[KnowledgeSource, ...]]] = {
    ReferenceKind.ATTACK_TECHNIQUE: (KnowledgeSource.MITRE,),
    ReferenceKind.ATTACK_TACTIC: (KnowledgeSource.MITRE,),
    ReferenceKind.ATTACK_GROUP: (KnowledgeSource.MITRE,),
    ReferenceKind.ATTACK_SOFTWARE: (KnowledgeSource.MITRE,),
    ReferenceKind.ATTACK_MITIGATION: (KnowledgeSource.MITRE,),
    ReferenceKind.ATTACK_DATA_SOURCE: (KnowledgeSource.MITRE,),
    ReferenceKind.ECS_FIELD: (KnowledgeSource.ECS,),
    ReferenceKind.SIGMA_RULE: (KnowledgeSource.SIGMA,),
    ReferenceKind.ELASTIC_RULE: (KnowledgeSource.ELASTIC,),
}

_NO_SOURCE_NOTE: Final[str] = "no loaded source answers this reference kind"
_NOT_FOUND_NOTE: Final[str] = "no record in the searched sources carries this identifier"


@final
class DefaultKnowledgeResolver:
    """Resolves references against a repository, without ever inventing a target."""

    __slots__ = ("_repository", "_normalizer", "_index", "_indexed")

    def __init__(
        self,
        repository: JsonlKnowledgeRepository,
        normalizer: DefaultKnowledgeNormalizer | None = None,
    ) -> None:
        """Build a resolver over one repository. No source is read yet."""
        self._repository = repository
        self._normalizer = normalizer if normalizer is not None else DefaultKnowledgeNormalizer()
        self._index: dict[KnowledgeSource, dict[str, tuple[KnowledgeRecord, ...]]] = {}
        self._indexed: set[KnowledgeSource] = set()

    def supported_kinds(self) -> tuple[str, ...]:
        """Return the reference kinds this resolver knows how to look up."""
        return tuple(kind.value for kind in KIND_SOURCES)

    def resolve(self, reference: KnowledgeReference) -> ResolutionResult:
        """Return what a reference points at, if anything."""
        sources = self._searchable(reference.kind)
        if not sources:
            return ResolutionResult(
                reference=reference,
                status=ResolutionStatus.UNRESOLVED,
                note=_NO_SOURCE_NOTE,
            )

        key = reference.value.strip().upper()
        candidates: list[KnowledgeRecord] = []
        for source in sources:
            candidates.extend(self._identifier_index(source).get(key, ()))

        if not candidates:
            return ResolutionResult(
                reference=reference,
                status=ResolutionStatus.UNRESOLVED,
                note=_NOT_FOUND_NOTE,
            )
        if len(candidates) > 1:
            return ResolutionResult(
                reference=reference,
                status=ResolutionStatus.AMBIGUOUS,
                records=tuple(candidates),
                note=f"{len(candidates)} records carry this identifier",
            )
        return ResolutionResult(
            reference=reference,
            status=ResolutionStatus.RESOLVED,
            records=(candidates[0],),
        )

    def resolve_all(self, references: Iterable[KnowledgeReference]) -> ResolutionReport:
        """Resolve several references, preserving their order."""
        return ResolutionReport(tuple(self.resolve(item) for item in references))

    def resolve_record(self, record: KnowledgeRecord) -> ResolutionReport:
        """Resolve every reference one record states."""
        return self.resolve_all(self._normalizer.references_of(record))

    def _searchable(self, kind: ReferenceKind) -> tuple[KnowledgeSource, ...]:
        """Return the loaded sources that can answer a reference kind."""
        available = self._repository.available_sources()
        return tuple(item for item in KIND_SOURCES.get(kind, ()) if item in available)

    def _identifier_index(
        self,
        source: KnowledgeSource,
    ) -> dict[str, tuple[KnowledgeRecord, ...]]:
        """Return a source's identifier index, building it on first use."""
        if source in self._indexed:
            return self._index[source]
        grouped: dict[str, list[KnowledgeRecord]] = {}
        for record in self._repository.iterate_source(source):
            for identifier in self._normalizer.normalize(record).identifiers:
                grouped.setdefault(identifier.strip().upper(), []).append(record)
        self._index[source] = {key: tuple(value) for key, value in grouped.items()}
        self._indexed.add(source)
        return self._index[source]
