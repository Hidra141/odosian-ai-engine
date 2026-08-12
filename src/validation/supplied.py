"""The supplied view.

A read-only projection of the context package that every check shares.

Built once per validation and passed to each checker, so the package is walked
a single time rather than once per citation, and so every check answers "was
this supplied?" from the same view rather than each forming its own opinion.

Nothing here mutates the package. The items are the package's own frozen
objects, held by reference; the derived collections are new containers over
them.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import final

from src.context.models import ContextItem, ContextPackage
from src.core.models import (
    EnhanceResult,
    Evidence,
    GenerateResult,
    OperationResult,
)
from src.core.uncertainty import UncertainIdentifier, uncertain_identifiers


@final
@dataclass(frozen=True, slots=True)
class SuppliedContext:
    """What the context package made available, indexed for checking."""

    items: Mapping[str, ContextItem]
    text: str
    ledger: Mapping[str, UncertainIdentifier]
    rule_query: str = ""
    """The query the package states for the rule under consideration.

    Empty for a format that carries no query string of its own — a Sigma rule
    states a detection map and a condition — in which case there is nothing for
    a result to reproduce and the checks that compare against it stand down.
    """

    @classmethod
    def of(cls, package: ContextPackage, rule_text: str = "") -> SuppliedContext:
        """Project one package into the view the checks read."""
        indexed = {item.item_id: item for item in package.items}
        parts: list[str] = [rule_text, package.rule_context.raw_text, package.rule_context.query]
        for item in package.items:
            parts.append(item.text)
            if item.source_id:
                parts.append(item.source_id)
            if item.provenance.parent_record_id:
                parts.append(item.provenance.parent_record_id)
        ledger = {entry.identifier: entry for entry in uncertain_identifiers(package)}
        return cls(
            items=MappingProxyType(indexed),
            text="\n".join(part for part in parts if part),
            ledger=MappingProxyType(ledger),
            rule_query=package.rule_context.query,
        )

    def item(self, item_id: str) -> ContextItem | None:
        """Return one supplied item by id, or ``None`` when it was never supplied."""
        return self.items.get(item_id)

    def supplies(self, identifier: str) -> bool:
        """Return whether an identifier occurs anywhere in the supplied material."""
        return bool(identifier) and identifier in self.text

    def is_unsettled(self, identifier: str) -> bool:
        """Return whether the context reported an identifier as unsettled."""
        return identifier in self.ledger


def citations(result: OperationResult) -> Iterator[tuple[str, Evidence]]:
    """Yield every citation a result carries, with the path that addresses it.

    Walks the result rather than calling ``cited_item_ids``, because a check
    needs to name *where* a bad citation sits, not merely that one exists.
    """
    for index, finding in enumerate(result.findings):
        for position, citation in enumerate(finding.evidence):
            yield f"findings[{index}].evidence[{position}]", citation
    if isinstance(result, EnhanceResult):
        for index, change in enumerate(result.changes):
            for position, citation in enumerate(change.evidence):
                yield f"changes[{index}].evidence[{position}]", citation
    if isinstance(result, GenerateResult):
        for index, entry in enumerate(result.rationale):
            for position, citation in enumerate(entry.evidence):
                yield f"rationale[{index}].evidence[{position}]", citation
        for index, mapping in enumerate(result.mappings):
            for position, citation in enumerate(mapping.evidence):
                yield f"mappings[{index}].evidence[{position}]", citation


def texts(result: OperationResult) -> Iterator[tuple[str, str]]:
    """Yield every free-text value a result carries, with its path.

    Used by the checks that scan what the result *says* rather than what it
    claims — credential shapes, prompt artefacts, invented citations.
    """
    yield "summary", result.summary
    for index, finding in enumerate(result.findings):
        yield f"findings[{index}].statement", finding.statement
        yield f"findings[{index}].explanation", finding.explanation
        for position, citation in enumerate(finding.evidence):
            yield f"findings[{index}].evidence[{position}].detail", citation.detail
    for index, recommendation in enumerate(result.recommendations):
        yield f"recommendations[{index}].action", recommendation.action
        yield f"recommendations[{index}].rationale", recommendation.rationale
    for index, entry in enumerate(result.uncertainties):
        yield f"uncertainties[{index}].treatment", entry.treatment
    for key in sorted(result.metadata):
        yield f"metadata.{key}", result.metadata[key]
    if isinstance(result, EnhanceResult):
        yield from _rule_texts("enhanced_rule", result.enhanced_rule)
        yield "original_rule.query", result.original_rule.query
        yield "original_rule.title", result.original_rule.title
        for index, change in enumerate(result.changes):
            yield f"changes[{index}].before", change.before
            yield f"changes[{index}].after", change.after
            yield f"changes[{index}].rationale", change.rationale
    if isinstance(result, GenerateResult):
        yield from _rule_texts("generated_rule", result.generated_rule)
        for index, decision in enumerate(result.rationale):
            yield f"rationale[{index}].statement", decision.statement
            yield f"rationale[{index}].rationale", decision.rationale


def _rule_texts(prefix: str, rule: object) -> Iterator[tuple[str, str]]:
    """Yield the free-text values of a produced rule."""
    for name in ("title", "description", "query", "investigation_guide"):
        yield f"{prefix}.{name}", str(getattr(rule, name))
    for index, value in enumerate(getattr(rule, "false_positives", ())):
        yield f"{prefix}.false_positives[{index}]", str(value)
    for index, value in enumerate(getattr(rule, "index_patterns", ())):
        yield f"{prefix}.index_patterns[{index}]", str(value)
