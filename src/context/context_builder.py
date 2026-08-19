"""Context construction.

Assembles the package Stage-15 consumes.

The order is fixed: convert every input into evidence, organise it into
sections, apply the budget, then attach the warnings and provenance produced
along the way. Each step is a separate module and none of them reaches back, so
the flow is the same on every run.

The builder performs no retrieval, opens no file, renders no prompt and calls no
model. It receives what earlier stages produced and arranges it.

Everything it emits is reproducible from its inputs. There are no timestamps, no
identifiers derived from object addresses, and no ordering that depends on
dictionary insertion beyond the fixed section order.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, final

from src.entities.models import ExtractedEntities
from src.graphrag.models import RetrievalResult
from src.mapping.models import MappedEntities
from src.parser.models import ParsedRule

from .budget import BudgetEnforcer
from .evidence import EvidenceBatch, EvidenceExtractor
from .exceptions import ContextBuildError, SecretLeakError
from .models import (
    ContextBudget,
    ContextItem,
    ContextPackage,
    ContextSection,
    ContextWarning,
    ItemProvenance,
    PackageProvenance,
    RuleContext,
)
from .organizer import EvidenceOrganizer
from .types import (
    ContextOperation,
    EvidenceKind,
    EvidencePriority,
    EvidenceStatus,
    SectionName,
    WarningCode,
)

_FORBIDDEN_ATTRIBUTES = ("reveal", "_value")

MAX_WARNING_SECTION_CHARS: Final[int] = 20_000
"""The most the rendered warnings section may hold.

The warnings section escapes the evidence budget so that a package can never
save characters by hiding what it did. That exemption is about honesty, not
about size, and without a ceiling of its own it let one rule render 1.6 million
characters of accounting around 52,000 characters of evidence.

The figure is a ceiling rather than a target. Nothing in the corpus approaches
it once repeated drops are stated once: it exists for the package that would
otherwise have no bound at all."""


def rule_context_from_parsed(rule: ParsedRule) -> RuleContext:
    """Build a rule context from a Stage-08 parsed rule.

    A convenience for the common case. The builder accepts a
    :class:`RuleContext` directly, so a caller with a rule from anywhere else is
    not forced through the parser.
    """
    return RuleContext(
        title=rule.metadata.title,
        identifier=rule.metadata.identifier or "",
        rule_format=rule.rule_format.value,
        language=rule.detection.language.value,
        query=rule.detection.query or "",
        condition=rule.condition.expression or "",
        log_source=_log_source(rule),
        tags=rule.tags,
        references=rule.references,
        false_positives=rule.false_positives,
        raw_text=rule.source_text,
    )


def _log_source(rule: ParsedRule) -> str:
    """Return a rule's log source rendered as one line."""
    source = rule.log_source
    parts = [
        f"category={source.category}" if source.category else "",
        f"product={source.product}" if source.product else "",
        f"service={source.service}" if source.service else "",
        f"indices={','.join(source.indices)}" if source.indices else "",
    ]
    return ", ".join(part for part in parts if part)


@final
@dataclass(frozen=True, slots=True)
class ContextBuilder:
    """Builds an auditable evidence package from upstream outputs."""

    budget: ContextBudget = field(default_factory=ContextBudget)
    extractor: EvidenceExtractor = field(default_factory=EvidenceExtractor)
    organizer: EvidenceOrganizer = field(default_factory=EvidenceOrganizer)

    def build(
        self,
        operation: ContextOperation,
        *,
        rule: RuleContext | ParsedRule | None = None,
        entities: ExtractedEntities | None = None,
        mappings: MappedEntities | None = None,
        retrieval: RetrievalResult | None = None,
    ) -> ContextPackage:
        """Assemble the context package for one operation."""
        # Screened before conversion: an unsupported type would otherwise raise
        # a build error and mask the fact that a credential holder was passed in.
        self._reject_secrets(rule, entities, mappings)
        rule_context = self._rule_context(rule)

        batches = (
            self.extractor.from_rule(rule_context),
            self.extractor.from_entities(entities),
            self.extractor.from_mappings(mappings),
            self.extractor.from_retrieval(retrieval),
            self.extractor.from_seeds(retrieval),
            self.extractor.from_references(rule_context),
        )
        items = [item for batch in batches for item in batch.items]
        warnings = [warning for batch in batches for warning in batch.warnings]

        sections = self.organizer.organize(items)
        outcome = BudgetEnforcer(budget=self.budget).apply(sections)
        warnings.extend(outcome.warnings)

        final_sections = self._with_reports(outcome.sections, warnings, operation, retrieval)
        return ContextPackage(
            operation=operation,
            rule_context=rule_context,
            sections=final_sections,
            budget=self.budget,
            warnings=tuple(warnings),
            provenance=self._provenance(operation, retrieval, entities, mappings),
        )

    def _rule_context(self, rule: RuleContext | ParsedRule | None) -> RuleContext:
        """Return the rule context, accepting either form or none."""
        if rule is None:
            return RuleContext()
        if isinstance(rule, RuleContext):
            return rule
        if isinstance(rule, ParsedRule):
            return rule_context_from_parsed(rule)
        raise ContextBuildError(f"unsupported rule input of type {type(rule).__name__}")

    def _reject_secrets(self, *inputs: object) -> None:
        """Refuse any input that looks like a credential holder.

        Redaction handles credential-shaped *text*. This guards the other
        direction: a caller passing a ``Secret`` or similar object in, which
        would mean secrets are believed to belong in context at all.
        """
        for candidate in inputs:
            if candidate is None:
                continue
            if all(hasattr(candidate, name) for name in _FORBIDDEN_ATTRIBUTES):
                raise SecretLeakError(
                    "context input",
                    f"{type(candidate).__name__} exposes a credential accessor",
                )

    def _warning_items(self, warnings: Sequence[ContextWarning]) -> tuple[ContextItem, ...]:
        """Return the warnings rendered, up to the section's own ceiling.

        Warnings are taken in the order they were raised and each is rendered
        whole, so the cut falls between two of them and never inside one. The
        closing notice is built after the loop from a count, which is why it
        cannot itself be cut and cannot produce a further warning.

        Room for that notice is set aside before the first warning is taken, so
        the ceiling holds for the section as it is finally written rather than
        for the section as it stood one line earlier. The reservation costs
        nothing when every warning fits, because then no notice is written.
        """
        room = MAX_WARNING_SECTION_CHARS - len(self._notice(len(warnings)))
        items: list[ContextItem] = []
        used = 0
        for index, warning in enumerate(warnings):
            text = str(warning)
            if used + len(text) > room:
                break
            items.append(self._warning_item(index, text, warning.code.value))
            used += len(text)
        omitted = len(warnings) - len(items)
        if omitted:
            items.append(
                self._warning_item(
                    len(items),
                    self._notice(omitted),
                    WarningCode.SECTION_BUDGET_EXCEEDED.value,
                )
            )
        return tuple(items)

    def _notice(self, omitted: int) -> str:
        """Return the one line that stands for the warnings not shown."""
        return (
            f"{omitted} further warning(s) were raised and are not shown here; "
            f"the section is limited to {MAX_WARNING_SECTION_CHARS} characters"
        )

    def _warning_item(self, index: int, text: str, code: str) -> ContextItem:
        """Return one rendered line of the warnings section."""
        return ContextItem(
            item_id=f"{SectionName.WARNINGS.value}:{index:04d}",
            section=SectionName.WARNINGS,
            kind=EvidenceKind.WARNING,
            text=text,
            evidence_status=EvidenceStatus.NOT_APPLICABLE,
            priority=EvidencePriority.UNSPECIFIED,
            provenance=ItemProvenance(origin="stage14:budget"),
            metadata={"code": code},
        )

    def _with_reports(
        self,
        sections: tuple[ContextSection, ...],
        warnings: list[ContextWarning],
        operation: ContextOperation,
        retrieval: RetrievalResult | None,
    ) -> tuple[ContextSection, ...]:
        """Append the warnings and metadata sections.

        Both are built after budgeting so they describe the package as it
        finally stands, and neither is subject to the budget itself: a package
        that hid its own warnings to save characters would be misleading.

        Escaping the budget is not licence to be unbounded. The account of a
        package is worth less than the package, and a rule that produced enough
        warnings to outweigh its own evidence would be handing a reader the
        accounting instead of the answer. :data:`MAX_WARNING_SECTION_CHARS` is
        where that stops. What is written is written whole — the section takes
        warnings until the next one would not fit and then stops, so no line is
        rendered half — and what is left out is counted in a single closing
        notice.

        That notice is written once, after the loop, and it is a rendered item
        rather than a warning. A warning about warnings would be a warning, and
        a package that answered a full warnings section by adding to it would
        never finish.

        Only the rendering is bounded. :attr:`ContextPackage.warnings` still
        carries every warning the build produced, so nothing is lost to a caller
        that reads them; what is bounded is what the prompt has to hold.
        """
        result = list(sections)
        if warnings:
            result.append(
                ContextSection(name=SectionName.WARNINGS, items=self._warning_items(warnings))
            )
        result.append(
            ContextSection(
                name=SectionName.METADATA,
                items=(
                    ContextItem(
                        item_id=f"{SectionName.METADATA.value}:0000",
                        section=SectionName.METADATA,
                        kind=EvidenceKind.METADATA,
                        text=self._metadata_text(operation, retrieval, result),
                        evidence_status=EvidenceStatus.NOT_APPLICABLE,
                        priority=EvidencePriority.UNSPECIFIED,
                        provenance=ItemProvenance(origin="stage14:metadata"),
                    ),
                ),
            )
        )
        return tuple(result)

    def _metadata_text(
        self,
        operation: ContextOperation,
        retrieval: RetrievalResult | None,
        sections: list[ContextSection],
    ) -> str:
        """Return the metadata block. Contains no timestamp, by design."""
        lines = [f"operation={operation.value}"]
        for section in sections:
            lines.append(
                f"section={section.name.value} items={len(section.items)} "
                f"chars={section.character_count} truncated={str(section.truncated).lower()}"
            )
        if retrieval is not None:
            lines.append(
                f"retrieval_mode={retrieval.mode.value} "
                f"items={len(retrieval.items)} candidates={retrieval.total_candidates}"
            )
        return "\n".join(lines)

    def _provenance(
        self,
        operation: ContextOperation,
        retrieval: RetrievalResult | None,
        entities: ExtractedEntities | None,
        mappings: MappedEntities | None,
    ) -> PackageProvenance:
        """Return the package-level account of where the inputs came from."""
        sources: tuple = ()
        mode = ""
        query_text = ""
        items = candidates = 0
        unresolved: tuple[str, ...] = ()
        ambiguous: tuple[str, ...] = ()
        redirected: tuple[tuple[str, str], ...] = ()
        if retrieval is not None:
            mode = retrieval.mode.value
            query_text = retrieval.query.text
            items = len(retrieval.items)
            candidates = retrieval.total_candidates
            seen: list = []
            for item in retrieval.items:
                if item.chunk.source not in seen:
                    seen.append(item.chunk.source)
            sources = tuple(seen)
            unresolved = tuple(seed.value for seed in retrieval.unresolved_seeds)
            ambiguous = tuple(seed.value for seed in retrieval.ambiguous_seeds)
            redirected = tuple(
                (seed.value, seed.resolved_value)
                for seed in retrieval.redirected_seeds
                if seed.resolved_value is not None
            )
        return PackageProvenance(
            operation=operation,
            retrieval_mode=mode,
            retrieval_query=query_text,
            retrieval_items=items,
            retrieval_candidates=candidates,
            sources_present=sources,
            unresolved_identifiers=unresolved,
            ambiguous_identifiers=ambiguous,
            redirected_identifiers=redirected,
            entity_count=len(entities) if entities is not None else 0,
            mapped_count=len(mappings) if mappings is not None else 0,
        )


def empty_batch() -> EvidenceBatch:
    """Return an empty evidence batch."""
    return EvidenceBatch()
