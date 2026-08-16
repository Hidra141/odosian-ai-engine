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

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, final

from src.context.models import ContextItem, ContextPackage
from src.core.identifiers import occurs_as_identifier
from src.core.models import (
    AnalyzeResult,
    DetectionRuleDraft,
    EnhanceResult,
    Evidence,
    GenerateResult,
    MappingClaim,
    MitreMapping,
    OperationResult,
)
from src.core.types import SupportLevel
from src.core.uncertainty import UncertainIdentifier, uncertain_identifiers

type AttackMapping = MitreMapping | MappingClaim
"""Either shape an ATT&CK mapping takes: a rule's own, or a claimed one."""

_WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")


@final
@dataclass(frozen=True, slots=True)
class SuppliedContext:
    """What the context package made available, indexed for checking."""

    items: Mapping[str, ContextItem]
    text: str
    folded: str
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
        text = "\n".join(part for part in parts if part)
        return cls(
            items=MappingProxyType(indexed),
            text=text,
            folded=fold(text),
            ledger=MappingProxyType(ledger),
            rule_query=package.rule_context.query,
        )

    def item(self, item_id: str) -> ContextItem | None:
        """Return one supplied item by id, or ``None`` when it was never supplied."""
        return self.items.get(item_id)

    def supplies(self, identifier: str) -> bool:
        """Return whether an identifier occurs in the supplied material as itself.

        Exact and case-sensitive, because an identifier must be reproduced as it
        was given: ``T1059.001`` and ``t1059.001`` are not the same identifier.

        The occurrence must be the whole identifier and not a piece of a longer
        one. Plain containment said material carrying ``T1059.001`` supplied
        ``T105``, which is how a technique nobody named could be asserted from a
        neighbouring one. The rule is
        :func:`src.core.identifiers.occurs_as_identifier`, shared with Stage-15
        so the two layers cannot answer this question differently.
        """
        return occurs_as_identifier(identifier, self.text)

    def mentions(self, phrase: str) -> bool:
        """Return whether a phrase occurs in the supplied material, loosely compared.

        For prose rather than identifiers — an ATT&CK technique's name, say.
        Case and runs of whitespace are ignored, so a name the material states
        across a line break still matches the same name written inline. This is
        deliberately looser than :meth:`supplies`: rejecting a correct name over
        a stray space would push the model toward omitting names it was given.
        """
        return bool(phrase.strip()) and fold(phrase) in self.folded

    def is_unsettled(self, identifier: str) -> bool:
        """Return whether the context reported an identifier as unsettled."""
        return identifier in self.ledger


def fold(text: str) -> str:
    """Return text with case and runs of whitespace flattened, for loose comparison."""
    return _WHITESPACE.sub(" ", text).strip().casefold()




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
    for index, mapping in enumerate(mapping_claims(result)):
        for position, citation in enumerate(mapping.evidence):
            yield f"mappings[{index}].evidence[{position}]", citation


def mapping_claims(result: OperationResult) -> tuple[MappingClaim, ...]:
    """Return the mapping claims a result states, or none for a result with no such field.

    An assessment states what the rule maps to and a generation states what the
    rule it wrote maps to. Both carry the same shape, so both are read the same
    way and neither can be reached by a check that knows only about the other.
    """
    if isinstance(result, AnalyzeResult | GenerateResult):
        return result.mappings
    return ()


def produced_rules(result: OperationResult) -> Iterator[tuple[str, DetectionRuleDraft]]:
    """Yield every rule a result produced, with the field it came from."""
    if isinstance(result, EnhanceResult):
        yield "enhanced_rule", result.enhanced_rule
    if isinstance(result, GenerateResult):
        yield "generated_rule", result.generated_rule


def attack_mappings(result: OperationResult) -> Iterator[tuple[str, AttackMapping]]:
    """Yield every ATT&CK mapping the result carries anywhere, with its path.

    The one traversal over mappings. A rule declares them and a claim states
    them, in two different types that agree on the fields that matter, and a
    property required of every mapping — a confidence inside its range, a name
    the material actually carries — is checked here once rather than once per
    place a mapping can sit.
    """
    for index, claim in enumerate(mapping_claims(result)):
        yield f"mappings[{index}]", claim
    for path, rule in produced_rules(result):
        for index, mapping in enumerate(rule.mitre):
            yield f"{path}.mitre[{index}]", mapping


def claimed_identifiers(result: OperationResult) -> Iterator[tuple[str, str, SupportLevel]]:
    """Yield every identifier a result claims outside a citation, with path and support.

    A mapping claim states its tactic and technique on the claim itself, not on
    the citations hanging off it, so :func:`citations` never reaches them and a
    check reading only citations would let an invented mapping through. Empty
    values are skipped: a mapping that states no tactic claims nothing, and
    there is nothing to look for in the supplied material.

    A rule's own ``mitre`` list is deliberately absent. The rule integrity check
    already holds those to the same standard under its own code, and yielding
    them here would report one fault twice.
    """
    for index, mapping in enumerate(mapping_claims(result)):
        for name, identifier in (
            ("tactic_id", mapping.tactic_id),
            ("technique_id", mapping.technique_id),
            ("parent_technique_id", mapping.parent_technique_id),
        ):
            value = identifier.strip()
            if value:
                yield f"mappings[{index}].{name}", value, mapping.support


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
        yield f"recommendations[{index}].code_snippet", recommendation.code_snippet
    for index, entry in enumerate(result.uncertainties):
        yield f"uncertainties[{index}].treatment", entry.treatment
    for key in sorted(result.metadata):
        yield f"metadata.{key}", result.metadata[key]
    for path, mapping in attack_mappings(result):
        yield f"{path}.tactic_name", mapping.tactic_name
        yield f"{path}.technique_name", mapping.technique_name
        yield f"{path}.parent_technique_name", mapping.parent_technique_name
    if isinstance(result, AnalyzeResult):
        for index, value in enumerate(result.strengths):
            yield f"strengths[{index}]", value
        for index, value in enumerate(result.weaknesses):
            yield f"weaknesses[{index}]", value
        for index, risk in enumerate(result.evasion_risks):
            yield f"evasion_risks[{index}].technique", risk.technique
            yield f"evasion_risks[{index}].description", risk.description
            yield f"evasion_risks[{index}].mitigation", risk.mitigation
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
        yield "notes", result.notes
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
    for index, value in enumerate(getattr(rule, "tags", ())):
        yield f"{prefix}.tags[{index}]", str(value)
