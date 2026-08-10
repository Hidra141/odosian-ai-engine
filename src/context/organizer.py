"""Evidence organisation.

Groups items into sections and fixes their order, deterministically.

**Stage-13's ranking is authoritative and is not recomputed.** Within a priority
class, items keep the exact order retrieval produced them in, carried on
``retrieval_rank``. The class itself comes from score components Stage-13
already assigned, so this module reads the ranking rather than competing with it.

Nothing is deduplicated. Two items with identical text can be two rules citing
one technique, or two chunks of one record — distinct evidence in both cases,
and collapsing them would destroy the plurality that makes the package
auditable.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import final

from .models import ContextItem, ContextSection
from .types import SECTION_ORDER, EvidencePriority, SectionName


def sort_key(item: ContextItem) -> tuple[int, int, float, int, str]:
    """Return the deterministic ordering key of an item.

    Ordered by: priority class, then Stage-13's rank where the item has one,
    then descending relevance, then ascending hop distance, then item id as a
    final tie-break so the result never depends on input order.
    """
    rank = item.retrieval_rank if item.retrieval_rank >= 0 else 1 << 30
    hops = item.provenance.hops if item.provenance.hops is not None else 1 << 20
    return (int(item.priority), rank, -item.relevance_score, hops, item.item_id)


@final
@dataclass(frozen=True, slots=True)
class EvidenceOrganizer:
    """Places items into sections in a fixed, reproducible order."""

    def organize(self, items: Sequence[ContextItem]) -> tuple[ContextSection, ...]:
        """Return the sections, in the fixed section order."""
        grouped: dict[SectionName, list[ContextItem]] = {}
        for item in items:
            grouped.setdefault(item.section, []).append(item)

        sections: list[ContextSection] = []
        for name in SECTION_ORDER:
            bucket = grouped.get(name)
            if not bucket:
                continue
            sections.append(
                ContextSection(name=name, items=tuple(self._ordered(name, bucket)))
            )
        return tuple(sections)

    def _ordered(self, name: SectionName, items: Sequence[ContextItem]) -> list[ContextItem]:
        """Return one section's items in their fixed order.

        Sections whose items are already in a meaningful sequence — the rule's
        own blocks, its references, the warnings — keep the order they were
        produced in. Evidence sections are sorted by priority.
        """
        if name in _SEQUENCE_PRESERVING:
            return list(items)
        return sorted(items, key=sort_key)


_SEQUENCE_PRESERVING: frozenset[SectionName] = frozenset(
    {
        SectionName.RULE,
        SectionName.ENTITIES,
        SectionName.MAPPINGS,
        SectionName.KNOWLEDGE,
        SectionName.REFERENCES,
        SectionName.WARNINGS,
        SectionName.METADATA,
    }
)
"""Sections whose production order already carries meaning.

Entities and mappings follow the rule's own field order; seed resolutions follow
the query's identifier order; the rule's blocks and references follow the rule.
Re-sorting any of them would discard information rather than add it.
"""


def priority_of(item: ContextItem) -> EvidencePriority:
    """Return an item's ordering class."""
    return item.priority
