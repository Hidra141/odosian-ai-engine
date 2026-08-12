"""Uncertainty ledger.

Reads the identifiers a context package could not settle, so the same list can
be shown to the model and demanded back from it.

This module owns no policy of its own. The context layer already decided what is
unresolved and what is ambiguous, and recorded it in two places: on the seed
resolution items it carries in the knowledge section, and on the package's
provenance. Both are read here and neither is second-guessed.

The ledger is what makes the safety property checkable in both directions. It
is rendered into the prompt so the model is told exactly what is unsettled, and
it is compared against the response so an identifier that arrived unresolved
cannot leave resolved, and an ambiguous one cannot leave narrowed to a single
candidate.

Only identifiers the retrieval layer reported on appear here. An entity mapping
that failed is visible in the context package's own text — Stage-14 renders its
status inline — but it carries no identifier field to key a ledger entry on, and
inventing one by parsing the rendered line would be exactly the kind of guess
this engine exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from src.context.models import ContextPackage
from src.context.types import EvidenceKind, EvidenceStatus

from .types import UncertaintyStatus

_IDENTIFIER_KEY: Final[str] = "identifier"
_CANDIDATES_KEY: Final[str] = "candidates"


@dataclass(frozen=True, slots=True)
class UncertainIdentifier:
    """One identifier the supplied context left unsettled."""

    identifier: str
    status: UncertaintyStatus
    candidates: tuple[str, ...] = ()
    item_id: str = ""

    def __str__(self) -> str:
        """Return the entry rendered for a prompt line."""
        candidates = ", ".join(self.candidates) if self.candidates else "none"
        where = f" [{self.item_id}]" if self.item_id else ""
        return f"{self.identifier}: {self.status.value} (candidates: {candidates}){where}"


def uncertain_identifiers(package: ContextPackage) -> tuple[UncertainIdentifier, ...]:
    """Return every unsettled identifier the package reports, in package order.

    Seed resolutions come first, in the order the retrieval layer produced them,
    each with the candidates it recorded. Identifiers named only on the
    package's provenance follow, in the order they appear there.
    """
    entries: list[UncertainIdentifier] = []
    seen: set[str] = set()
    for item in package.items:
        if item.kind is not EvidenceKind.SEED_RESOLUTION:
            continue
        status = _status_of(item.evidence_status)
        if status is None:
            continue
        identifier = item.metadata.get(_IDENTIFIER_KEY, "").strip()
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        entries.append(
            UncertainIdentifier(
                identifier=identifier,
                status=status,
                candidates=_candidates(item.metadata.get(_CANDIDATES_KEY, "")),
                item_id=item.item_id,
            )
        )
    provenance = package.provenance
    if provenance is None:
        return tuple(entries)
    for identifier in provenance.unresolved_identifiers:
        if identifier and identifier not in seen:
            seen.add(identifier)
            entries.append(UncertainIdentifier(identifier, UncertaintyStatus.UNRESOLVED))
    for identifier in provenance.ambiguous_identifiers:
        if identifier and identifier not in seen:
            seen.add(identifier)
            entries.append(UncertainIdentifier(identifier, UncertaintyStatus.AMBIGUOUS))
    return tuple(entries)


def _status_of(status: EvidenceStatus) -> UncertaintyStatus | None:
    """Return the ledger status of an evidence status, or ``None`` when settled."""
    if status is EvidenceStatus.UNRESOLVED:
        return UncertaintyStatus.UNRESOLVED
    if status is EvidenceStatus.AMBIGUOUS:
        return UncertaintyStatus.AMBIGUOUS
    return None


def _candidates(value: str) -> tuple[str, ...]:
    """Return the candidate list a seed item recorded, in its own order."""
    return tuple(part.strip() for part in value.split(",") if part.strip())
