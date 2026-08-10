"""Reference reading.

Reads the references a record *states* out of its own metadata.

Each source states them differently — ``mitreTechniques`` in Sigma, ``mitre`` in
Elastic, ``mitreTechnique`` in LOLBAS, ``tactics`` and ``parentTechniqueId`` in
MITRE — so the rules are written out per source rather than hidden behind a
guess about field names. Every rule is a literal field read.

Nothing is inferred. Prose in ``text`` is not scanned, a technique is not
derived from a tactic, and a record that states no references yields none. A
LOLBAS entry with ``mitreTechnique: null`` produces an empty tuple, which is the
truthful answer for the 891 entries that carry no linkage.

Identifier *syntax* is normalised — ``t1059`` and ``T1059`` denote the same
technique — but nothing is looked up here. Whether the target exists is the
resolver's question.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from typing import Final

from ..models.records import KnowledgeRecord, KnowledgeReference
from ..models.types import KnowledgeSource, ReferenceKind

_TECHNIQUE: Final[re.Pattern[str]] = re.compile(r"\AT\d{4}(?:\.\d{3})?\Z", re.IGNORECASE)
_TACTIC: Final[re.Pattern[str]] = re.compile(r"\ATA\d{4}\Z", re.IGNORECASE)
_GROUP: Final[re.Pattern[str]] = re.compile(r"\AG\d{4}\Z", re.IGNORECASE)
_SOFTWARE: Final[re.Pattern[str]] = re.compile(r"\AS\d{4}\Z", re.IGNORECASE)
_MITIGATION: Final[re.Pattern[str]] = re.compile(r"\AM\d{4}\Z", re.IGNORECASE)
_DATA_SOURCE: Final[re.Pattern[str]] = re.compile(r"\ADS\d{4}\Z", re.IGNORECASE)
_CVE: Final[re.Pattern[str]] = re.compile(r"\ACVE-\d{4}-\d{4,}\Z", re.IGNORECASE)

_ATTACK_TAG_PREFIX: Final[str] = "attack."


def classify_identifier(value: str) -> ReferenceKind:
    """Return the kind an ATT&CK-style identifier belongs to, by syntax alone."""
    token = value.strip()
    for pattern, kind in (
        (_DATA_SOURCE, ReferenceKind.ATTACK_DATA_SOURCE),
        (_TACTIC, ReferenceKind.ATTACK_TACTIC),
        (_TECHNIQUE, ReferenceKind.ATTACK_TECHNIQUE),
        (_GROUP, ReferenceKind.ATTACK_GROUP),
        (_SOFTWARE, ReferenceKind.ATTACK_SOFTWARE),
        (_MITIGATION, ReferenceKind.ATTACK_MITIGATION),
        (_CVE, ReferenceKind.CVE),
    ):
        if pattern.match(token):
            return kind
    return ReferenceKind.UNKNOWN


def canonical_identifier(value: str, kind: ReferenceKind) -> str:
    """Return an identifier in its conventional case, unchanged otherwise."""
    token = value.strip()
    if kind is ReferenceKind.CVE:
        return token.upper()
    if kind is ReferenceKind.UNKNOWN:
        return token
    return token.upper()


def references_of(record: KnowledgeRecord) -> tuple[KnowledgeReference, ...]:
    """Return every reference a record states, in the order it states them."""
    readers = {
        KnowledgeSource.MITRE: _mitre_references,
        KnowledgeSource.SIGMA: _sigma_references,
        KnowledgeSource.ELASTIC: _elastic_references,
        KnowledgeSource.LOLBAS: _lolbas_references,
        KnowledgeSource.ECS: _ecs_references,
    }
    reader = readers.get(record.source)
    if reader is None:
        return ()
    return tuple(reader(record))


def _reference(
    record: KnowledgeRecord,
    value: str,
    field: str,
    kind: ReferenceKind | None = None,
) -> KnowledgeReference | None:
    """Build a reference from a stated value, or nothing when it is empty."""
    token = value.strip()
    if not token:
        return None
    resolved_kind = kind if kind is not None else classify_identifier(token)
    return KnowledgeReference(
        kind=resolved_kind,
        value=canonical_identifier(token, resolved_kind),
        origin_source=record.source,
        origin_record_id=record.id,
        origin_field=field,
    )


def _strings(value: object) -> Sequence[str]:
    """Return the string members of a value, accepting a scalar or a sequence."""
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _mitre_references(record: KnowledgeRecord) -> Iterator[KnowledgeReference]:
    """Read the references a MITRE record states."""
    for field in ("parentTechniqueId",):
        for value in _strings(record.metadata_value(field)):
            reference = _reference(record, value, field)
            if reference is not None:
                yield reference
    for value in _strings(record.metadata_value("tactics")):
        reference = _reference(record, value, "tactics", ReferenceKind.ATTACK_TACTIC)
        if reference is not None:
            yield reference


def _sigma_references(record: KnowledgeRecord) -> Iterator[KnowledgeReference]:
    """Read the references a Sigma record states."""
    for value in _strings(record.metadata_value("mitreTechniques")):
        reference = _reference(record, value, "mitreTechniques")
        if reference is not None:
            yield reference
    for value in _strings(record.metadata_value("tags")):
        token = value.strip()
        if not token.lower().startswith(_ATTACK_TAG_PREFIX):
            continue
        tail = token[len(_ATTACK_TAG_PREFIX) :]
        kind = classify_identifier(tail)
        if kind is ReferenceKind.UNKNOWN:
            continue
        reference = _reference(record, tail, "tags", kind)
        if reference is not None:
            yield reference


def _elastic_references(record: KnowledgeRecord) -> Iterator[KnowledgeReference]:
    """Read the references an Elastic record states."""
    entries = record.metadata_value("mitre")
    if not isinstance(entries, (list, tuple)):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for field, kind in (
            ("tacticId", ReferenceKind.ATTACK_TACTIC),
            ("techniqueId", ReferenceKind.ATTACK_TECHNIQUE),
        ):
            value = entry.get(field)
            if isinstance(value, str):
                reference = _reference(record, value, f"mitre.{field}", kind)
                if reference is not None:
                    yield reference


def _lolbas_references(record: KnowledgeRecord) -> Iterator[KnowledgeReference]:
    """Read the references a LOLBAS record states."""
    for value in _strings(record.metadata_value("mitreTechnique")):
        reference = _reference(record, value, "mitreTechnique")
        if reference is not None:
            yield reference


def _ecs_references(record: KnowledgeRecord) -> Iterator[KnowledgeReference]:
    """Read the references an ECS record states.

    ECS field definitions state no cross-source references. Returning nothing is
    the accurate answer, not a gap.
    """
    return iter(())
