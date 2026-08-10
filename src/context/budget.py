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
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, final

from .exceptions import ContextBudgetExceededError
from .models import ContextBudget, ContextItem, ContextSection, ContextWarning
from .types import TruncationPolicy, WarningCode

TRUNCATION_MARKER: Final[str] = "\n[...truncated]"


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
        return self._cap_total(capped, warnings)

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
