"""Context validation.

Checks a built package before it leaves this layer.

The checks are integrity and safety properties, not quality judgements. An empty
package is valid; one whose retrieved evidence has lost its chunk id is not, and
one that still contains a credential-shaped value is not, and one that reports an
unresolved identifier as resolved is not.

Every issue is collected before reporting, so a single run names every problem.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import final

from .evidence import _CREDENTIAL_PATTERNS
from .exceptions import ContextValidationError
from .models import ContextItem, ContextPackage
from .organizer import sort_key
from .types import SECTION_ORDER, EvidenceKind, EvidenceStatus, SectionName


@dataclass(frozen=True, slots=True)
class ContextIssue:
    """One problem found in a package."""

    check: str
    detail: str

    def __str__(self) -> str:
        """Return the issue rendered as ``check: detail``."""
        return f"{self.check}: {self.detail}"


@dataclass(frozen=True, slots=True)
class ContextValidationResult:
    """The outcome of validating a package."""

    issues: tuple[ContextIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        """Return whether the package passed every check."""
        return not self.issues

    def raise_if_invalid(self) -> None:
        """Raise :class:`ContextValidationError` when any issue was found."""
        if self.issues:
            raise ContextValidationError([str(item) for item in self.issues])


@final
class ContextValidator:
    """Checks a context package for integrity and safety."""

    __slots__ = ()

    def validate(self, package: ContextPackage) -> ContextValidationResult:
        """Run every check and collect the issues."""
        return ContextValidationResult(
            (
                *self._budget(package),
                *self._duplicate_ids(package),
                *self._provenance(package),
                *self._ordering(package),
                *self._status_integrity(package),
                *self._truncation_marked(package),
                *self._secrets(package),
                *self._section_order(package),
            )
        )

    def _budget(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue when the package exceeds what it was allowed."""
        allowed = package.budget.available_chars
        if allowed > 0 and package.evidence_characters > allowed:
            yield ContextIssue(
                "total_budget_exceeded",
                f"{package.evidence_characters} evidence characters against "
                f"{allowed} available",
            )
        limit = package.budget.max_section_chars
        if limit <= 0:
            return
        for section in package.sections:
            if section.name in _UNBUDGETED:
                continue
            if section.character_count > limit:
                yield ContextIssue(
                    "section_budget_exceeded",
                    f"{section.name.value} holds {section.character_count}, limit is {limit}",
                )

    def _duplicate_ids(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue for any item id used twice."""
        seen: dict[str, int] = {}
        for item in package.items:
            seen[item.item_id] = seen.get(item.item_id, 0) + 1
        for item_id, count in seen.items():
            if count > 1:
                yield ContextIssue("duplicate_item_id", f"{item_id} appears {count} times")

    def _provenance(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue for retrieved evidence that cannot be traced home."""
        for item in package.items:
            if item.kind not in _RETRIEVED_KINDS:
                continue
            provenance = item.provenance
            missing = [
                name
                for name, value in (
                    ("chunk_id", provenance.chunk_id),
                    ("parent_record_id", provenance.parent_record_id),
                    ("source_id", provenance.source_id),
                    ("dataset_location", provenance.dataset_location),
                )
                if not value
            ]
            if provenance.source is None:
                missing.append("source")
            if missing:
                yield ContextIssue(
                    "missing_provenance",
                    f"{item.item_id} lacks {', '.join(missing)}",
                )
            # A seed node is where traversal started, so it has no path leading
            # to it. Only a neighbour reached by walking must carry one.
            if (
                item.kind is EvidenceKind.RETRIEVED_GRAPH
                and provenance.hops is not None
                and provenance.hops > 0
                and not provenance.graph_paths
            ):
                yield ContextIssue(
                    "missing_graph_path",
                    f"{item.item_id} was reached in {provenance.hops} hops but carries no path",
                )

    def _ordering(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue when a sorted section is not in its sorted order."""
        for section in package.sections:
            if section.name in _SEQUENCE_PRESERVING:
                continue
            keys = [sort_key(item) for item in section.items]
            if keys != sorted(keys):
                yield ContextIssue(
                    "unordered_section",
                    f"{section.name.value} is not in deterministic order",
                )

    def _status_integrity(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue when an unresolved identifier is presented as settled."""
        for item in package.items:
            if item.kind is not EvidenceKind.SEED_RESOLUTION:
                continue
            declared = item.metadata.get("status", "").strip().lower()
            if declared == "unresolved" and item.evidence_status is not EvidenceStatus.UNRESOLVED:
                yield ContextIssue(
                    "unresolved_reported_as_resolved",
                    f"{item.item_id} declares {declared} but carries "
                    f"{item.evidence_status.value}",
                )
            if declared == "ambiguous":
                if item.evidence_status is not EvidenceStatus.AMBIGUOUS:
                    yield ContextIssue(
                        "ambiguous_reported_as_resolved",
                        f"{item.item_id} declares ambiguous but carries "
                        f"{item.evidence_status.value}",
                    )
                expected = item.metadata.get("candidate_count", "0")
                listed = [c for c in item.metadata.get("candidates", "").split(",") if c]
                if str(len(listed)) != expected:
                    yield ContextIssue(
                        "ambiguous_candidates_lost",
                        f"{item.item_id} declares {expected} candidates but lists {len(listed)}",
                    )

    def _truncation_marked(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue when a shortened item is not marked as such."""
        for item in package.items:
            if item.truncated and item.original_length <= item.char_length:
                yield ContextIssue(
                    "truncation_not_recorded",
                    f"{item.item_id} is marked truncated but records no original length",
                )
            if not item.truncated and item.original_length > item.char_length:
                yield ContextIssue(
                    "silent_truncation",
                    f"{item.item_id} is shorter than its original but is not marked",
                )

    def _secrets(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue for any credential-shaped value that survived redaction."""
        for item in package.items:
            for name, pattern in _CREDENTIAL_PATTERNS:
                match = pattern.search(item.text)
                if match is not None and "[REDACTED]" not in match.group(0):
                    yield ContextIssue(
                        "credential_in_context",
                        f"{item.item_id} matches the {name} pattern",
                    )

    def _section_order(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue when sections are not in the fixed order."""
        order = [section.name for section in package.sections]
        expected = [name for name in SECTION_ORDER if name in set(order)]
        if order != expected:
            yield ContextIssue(
                "section_order",
                f"sections appear as {[n.value for n in order]}",
            )

    def validate_utf8(self, package: ContextPackage) -> Iterator[ContextIssue]:
        """Yield an issue for any item whose text will not round-trip as UTF-8."""
        for item in package.items:
            try:
                item.text.encode("utf-8").decode("utf-8")
            except UnicodeError:
                yield ContextIssue("invalid_utf8", item.item_id)


_RETRIEVED_KINDS: frozenset[EvidenceKind] = frozenset(
    {EvidenceKind.RETRIEVED_TEXT, EvidenceKind.RETRIEVED_GRAPH}
)

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

_UNBUDGETED: frozenset[SectionName] = frozenset(
    {SectionName.WARNINGS, SectionName.METADATA}
)
"""Sections built after budgeting, describing the package rather than filling it."""


def item_summary(item: ContextItem) -> str:
    """Return a one-line summary of an item, without its text."""
    return (
        f"{item.item_id} kind={item.kind.value} status={item.evidence_status.value} "
        f"chars={item.char_length} truncated={str(item.truncated).lower()}"
    )
