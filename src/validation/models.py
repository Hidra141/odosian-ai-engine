"""Validation report.

One issue, and the report that collects them.

The report is a value object: it carries what was found and answers questions
about it, but it never repairs anything and never holds the result it judged.
A caller that wants the result keeps its own reference; a caller that wants to
refuse it reads :attr:`ValidationReport.is_valid`.

There is no timestamp and no identifier generated at construction, so two runs
over the same result produce two equal reports.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from src.core.types import ReasoningOperation

from .types import CategoryOrder, IssueSeverity, ValidationCategory, ValidationCode


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One problem found in a reasoning result.

    ``path`` addresses the offending value the way the response document spells
    it — ``findings[0].evidence[1].item_id`` — so an issue can be pointed at
    without the reader guessing which of five findings is meant.
    """

    code: ValidationCode
    severity: IssueSeverity
    path: str
    message: str

    @property
    def category(self) -> ValidationCategory:
        """Return the category of this issue, taken from its code."""
        return self.code.category

    @property
    def blocks(self) -> bool:
        """Return whether this issue prevents the result being accepted."""
        return self.severity is IssueSeverity.ERROR

    @property
    def sort_key(self) -> tuple[int, str, str, str]:
        """Return the deterministic ordering key of this issue."""
        return (CategoryOrder.of(self.category), self.path, self.code.value, self.message)

    def __str__(self) -> str:
        """Return the issue rendered for a report line."""
        return f"{self.severity.value} {self.code.value} at {self.path}: {self.message}"


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """What validating one result found.

    Issues arrive already ordered by :meth:`of`, so the report a caller receives
    is identical for identical inputs regardless of the order the checks ran in.
    """

    operation: ReasoningOperation
    issues: tuple[ValidationIssue, ...] = field(default_factory=tuple)

    @classmethod
    def of(
        cls,
        operation: ReasoningOperation,
        issues: Sequence[ValidationIssue],
    ) -> ValidationReport:
        """Build a report, ordering the issues deterministically."""
        return cls(operation=operation, issues=tuple(sorted(issues, key=lambda i: i.sort_key)))

    @property
    def is_valid(self) -> bool:
        """Return whether the result may be accepted.

        Warnings do not block. An issue that should stop a result reaching the
        caller is recorded as an error, and the distinction is the point of
        having severities at all.
        """
        return not any(issue.blocks for issue in self.issues)

    @property
    def issue_count(self) -> int:
        """Return how many issues were found, blocking or not."""
        return len(self.issues)

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        """Return only the blocking issues, in report order."""
        return tuple(issue for issue in self.issues if issue.blocks)

    @property
    def warnings(self) -> tuple[ValidationIssue, ...]:
        """Return only the non-blocking issues, in report order."""
        return tuple(issue for issue in self.issues if not issue.blocks)

    def of_category(self, category: ValidationCategory) -> tuple[ValidationIssue, ...]:
        """Return the issues of one category, in report order."""
        return tuple(issue for issue in self.issues if issue.category is category)

    def codes(self) -> tuple[ValidationCode, ...]:
        """Return the code of every issue, in report order."""
        return tuple(issue.code for issue in self.issues)

    def __iter__(self) -> Iterator[ValidationIssue]:
        """Iterate the issues in report order."""
        return iter(self.issues)

    def __len__(self) -> int:
        """Return how many issues the report holds."""
        return len(self.issues)

    def summary(self) -> str:
        """Return a one-line account of the report."""
        verdict = "valid" if self.is_valid else "invalid"
        return (
            f"{self.operation.value}: {verdict}, {len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s)"
        )
