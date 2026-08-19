"""Budgeting.

Keeps a package inside its character limits, deterministically and audibly.

Reduction never happens quietly. Every cut produces a warning naming the item,
the item itself is marked truncated and keeps its original length, and the
section it sits in is marked too. A caller can always tell the difference
between "the corpus said this much" and "this is what fitted".

Cuts are made on character boundaries. Python strings are sequences of code
points, so a slice always re-encodes to valid UTF-8; the marker appended to a
cut item is counted against the budget rather than pushing it over.

No summarisation happens here. Shortening by meaning would be reasoning, which
belongs to Stage-15 — this module only decides what fits.

A cut that removes many items reports them as one warning rather than many. The
report is per *reason*, not per item: a package whose entity section outgrew the
budget by four thousand items produced four thousand warnings that differed only
in an identifier nothing reads, saying the same three sentences over and over,
and the account of the cut grew faster than the thing it was accounting for. The
count is what a reader needs, so the count is what is kept, beside the first
item it happened to. A reason that cut exactly one item still reads exactly as
it did before.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, final

from .exceptions import ContextBudgetExceededError
from .models import ContextBudget, ContextItem, ContextSection, ContextWarning
from .types import SectionName, TruncationPolicy, WarningCode

TRUNCATION_MARKER: Final[str] = "\n[...truncated]"


_Reason = tuple[str, "SectionName | None"]
"""What makes two drops the same drop: one sentence, in one section."""


def collapse_dropped(
    warnings: Sequence[ContextWarning],
) -> tuple[ContextWarning, ...]:
    """Return the warnings with repeated drops of one reason stated once.

    Only :attr:`~src.context.types.WarningCode.ITEM_DROPPED` is folded, and only
    across warnings that already agree on their section *and* their reason. Two
    sections starved by the same sentence stay two warnings, because which
    section lost its evidence is the part a reader acts on.

    Nothing else is touched. An unresolved reference names the value that failed
    to resolve and the reason it did, so two of them are two different facts and
    folding them would delete one; the same is true of every other code. Drops
    are the exception because their reason comes from a closed set of three
    sentences and the only thing that varies is an item identifier no stage
    reads.

    A reason that dropped one item is returned unchanged, so the common case is
    byte-for-byte what it was. A reason that dropped several keeps the first item
    it happened to and states how many followed. Order is the order the reasons
    first occurred, so the same package always reports them the same way.
    """
    first: dict[_Reason, ContextWarning] = {}
    counts: dict[_Reason, int] = {}
    order: list[ContextWarning | _Reason] = []
    for warning in warnings:
        if warning.code is not WarningCode.ITEM_DROPPED:
            order.append(warning)
            continue
        reason: _Reason = (warning.detail, warning.section)
        if reason not in counts:
            first[reason] = warning
            counts[reason] = 1
            order.append(reason)
        else:
            counts[reason] += 1
    return tuple(
        item
        if isinstance(item, ContextWarning)
        else _stated(first[item], counts[item])
        for item in order
    )


def _stated(first: ContextWarning, count: int) -> ContextWarning:
    """Return one warning standing for ``count`` drops of the same reason."""
    if count == 1:
        return first
    return ContextWarning(
        code=first.code,
        detail=f"{first.detail} ({count} items, first {first.item_id})",
        item_id=first.item_id,
        section=first.section,
    )


@dataclass(frozen=True, slots=True)
class BudgetOutcome:
    """The sections after budgeting, and what it cost."""

    sections: tuple[ContextSection, ...] = ()
    warnings: tuple[ContextWarning, ...] = ()

    @property
    def total_characters(self) -> int:
        """Return the characters the sections now hold."""
        return sum(section.character_count for section in self.sections)


@final
@dataclass(frozen=True, slots=True)
class BudgetEnforcer:
    """Applies section and total limits to organised sections."""

    budget: ContextBudget

    def apply(self, sections: Sequence[ContextSection]) -> BudgetOutcome:
        """Return the sections reduced to fit, with a warning for every cut."""
        warnings: list[ContextWarning] = []
        capped = [self._cap_section(section, warnings) for section in sections]
        outcome = self._cap_total(capped, warnings)
        return BudgetOutcome(outcome.sections, collapse_dropped(outcome.warnings))

    def _cap_section(
        self,
        section: ContextSection,
        warnings: list[ContextWarning],
    ) -> ContextSection:
        """Reduce one section to the per-section limit."""
        limit = self.budget.max_section_chars
        if limit <= 0 or section.character_count <= limit:
            return section
        if self.budget.policy is TruncationPolicy.NONE:
            raise ContextBudgetExceededError(
                section.character_count, limit, self.budget.policy.value
            )
        warnings.append(
            ContextWarning(
                code=WarningCode.SECTION_BUDGET_EXCEEDED,
                detail=(
                    f"section holds {section.character_count} characters, "
                    f"limit is {limit}"
                ),
                section=section.name,
            )
        )
        kept, used = self._fit(list(section.items), limit, warnings)
        return section.with_items(kept, truncated=used < section.character_count)

    def _cap_total(
        self,
        sections: Sequence[ContextSection],
        warnings: list[ContextWarning],
    ) -> BudgetOutcome:
        """Reduce the package to the total limit, section by section."""
        allowed = self.budget.available_chars
        total = sum(section.character_count for section in sections)
        if allowed <= 0 or total <= allowed:
            return BudgetOutcome(tuple(sections), tuple(warnings))
        if self.budget.policy is TruncationPolicy.NONE:
            raise ContextBudgetExceededError(total, allowed, self.budget.policy.value)

        warnings.append(
            ContextWarning(
                code=WarningCode.TOTAL_BUDGET_EXCEEDED,
                detail=f"context holds {total} characters, {allowed} are available",
            )
        )
        remaining = allowed
        result: list[ContextSection] = []
        for section in sections:
            if remaining <= 0:
                for item in section.items:
                    warnings.append(
                        ContextWarning(
                            code=WarningCode.ITEM_DROPPED,
                            detail="no budget remained for this item",
                            item_id=item.item_id,
                            section=section.name,
                        )
                    )
                result.append(section.with_items((), truncated=True))
                continue
            kept, used = self._fit(list(section.items), remaining, warnings)
            remaining -= used
            result.append(
                section.with_items(kept, truncated=used < section.character_count)
            )
        return BudgetOutcome(tuple(result), tuple(warnings))

    def _fit(
        self,
        items: Sequence[ContextItem],
        limit: int,
        warnings: list[ContextWarning],
    ) -> tuple[list[ContextItem], int]:
        """Fit items into a character limit, keeping the earliest whole.

        Items are already in priority order, so taking them from the front keeps
        the strongest evidence. The item that crosses the boundary is trimmed
        under ``TRIM_TAIL`` and dropped under ``DROP_LOWEST_PRIORITY``.
        """
        kept: list[ContextItem] = []
        used = 0
        for index, item in enumerate(items):
            room = limit - used
            if room <= 0:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.ITEM_DROPPED,
                        detail="no budget remained for this item",
                        item_id=item.item_id,
                        section=item.section,
                    )
                )
                continue
            if item.char_length <= room:
                kept.append(item)
                used += item.char_length
                continue
            if self.budget.policy is TruncationPolicy.DROP_LOWEST_PRIORITY:
                for dropped in items[index:]:
                    warnings.append(
                        ContextWarning(
                            code=WarningCode.ITEM_DROPPED,
                            detail="dropped whole to stay within budget",
                            item_id=dropped.item_id,
                            section=dropped.section,
                        )
                    )
                break
            trimmed = self._trim(item, room)
            if trimmed is None:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.ITEM_DROPPED,
                        detail="remaining budget too small to hold any of this item",
                        item_id=item.item_id,
                        section=item.section,
                    )
                )
                continue
            warnings.append(
                ContextWarning(
                    code=WarningCode.ITEM_TRUNCATED,
                    detail=f"kept {trimmed.char_length} of {item.char_length} characters",
                    item_id=item.item_id,
                    section=item.section,
                )
            )
            kept.append(trimmed)
            used += trimmed.char_length
        return kept, used

    def _trim(self, item: ContextItem, room: int) -> ContextItem | None:
        """Return the item cut to fit, or ``None`` when it cannot usefully fit.

        The marker is counted inside the allowance, so a trimmed item never
        exceeds the room it was given.
        """
        if room <= len(TRUNCATION_MARKER):
            return None
        body = item.text[: room - len(TRUNCATION_MARKER)]
        return item.with_text(body + TRUNCATION_MARKER, truncated=True)
