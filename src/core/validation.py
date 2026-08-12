"""Reasoning validation.

The checks that stand between a well-formed response and a trustworthy one.

Structure is already settled by the time this runs: the schema validator has
established that every field is present, correctly typed and inside its
enumeration. What is left is the harder question — whether the response says
anything the supplied context does not entitle it to say.

Five properties are enforced:

* **The response answers the request.** Its operation is the operation that was
  asked for, and the artefact that operation must produce is present.
* **Its internal references hold.** Ids are unique, and a recommendation or a
  change that claims to answer a finding names a finding that exists.
* **Its citations point at supplied material.** Every cited item id is an id the
  context package actually carries. A citation of an item that was never
  supplied is a fabricated reference, and it is rejected as one.
* **Its identifiers were supplied.** An ATT&CK or ECS identifier appearing in a
  citation, a mapping or a produced rule must occur in the supplied material.
  The engine never lets a model introduce an identifier it was not given.
* **Uncertainty survives.** Every identifier the context reports unresolved or
  ambiguous is carried forward with that same status; an ambiguous identifier
  keeps all of its candidates; no claim resting on an unsettled identifier is
  presented as established; and no produced rule maps to one.

Every issue is collected before anything is raised, so one run reports every
problem rather than the first. This mirrors the validators of Stage-06 and
Stage-14 rather than introducing a second convention.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, final

from src.context.models import ContextPackage

from .exceptions import ReasoningValidationError
from .models import (
    AnalyzeResult,
    DetectionRuleDraft,
    EnhanceResult,
    Evidence,
    GenerateResult,
    OperationResult,
    ReasoningRequest,
)
from .types import ReasoningOperation, SupportLevel
from .uncertainty import UncertainIdentifier, uncertain_identifiers

_WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class ReasoningIssue:
    """One problem found in a response."""

    check: str
    detail: str

    def __str__(self) -> str:
        """Return the issue rendered as ``check: detail``."""
        return f"{self.check}: {self.detail}"


@dataclass(frozen=True, slots=True)
class ReasoningValidationResult:
    """The outcome of validating a response."""

    operation: ReasoningOperation
    issues: tuple[ReasoningIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        """Return whether the response passed every check."""
        return not self.issues

    def raise_if_invalid(self) -> None:
        """Raise :class:`ReasoningValidationError` when any issue was found."""
        if self.issues:
            raise ReasoningValidationError(
                self.operation.value, [str(issue) for issue in self.issues]
            )


@dataclass(frozen=True, slots=True)
class SuppliedMaterial:
    """What the context package made available to the model.

    Built once per validation so every check reads the same view of what was
    supplied, and so the package is walked once rather than per citation.
    """

    item_ids: frozenset[str]
    text: str

    @classmethod
    def of(cls, package: ContextPackage, rule_text: str) -> SuppliedMaterial:
        """Collect the addressable ids and the searchable text of one package."""
        parts: list[str] = [rule_text]
        ids: set[str] = set()
        for item in package.items:
            ids.add(item.item_id)
            parts.append(item.text)
            if item.source_id:
                parts.append(item.source_id)
            if item.provenance.parent_record_id:
                parts.append(item.provenance.parent_record_id)
        return cls(item_ids=frozenset(ids), text="\n".join(parts))

    def supplies(self, identifier: str) -> bool:
        """Return whether an identifier occurs in the supplied material."""
        return identifier in self.text


@final
@dataclass(frozen=True, slots=True)
class ReasoningValidator:
    """Checks a typed result against the request that produced it."""

    def validate(
        self,
        result: OperationResult,
        request: ReasoningRequest,
    ) -> ReasoningValidationResult:
        """Run every check and collect the issues."""
        material = SuppliedMaterial.of(request.package, request.rule_context.raw_text)
        ledger = uncertain_identifiers(request.package)
        issues = (
            *self._operation(result, request),
            *self._identifiers(result),
            *self._references(result),
            *self._citations(result, material),
            *self._cited_identifiers(result, material),
            *self._uncertainty_carried(result, ledger),
            *self._uncertainty_not_promoted(result, ledger),
            *self._rule_output(result, request, material),
        )
        return ReasoningValidationResult(request.operation, issues)

    def _operation(
        self,
        result: OperationResult,
        request: ReasoningRequest,
    ) -> Iterator[ReasoningIssue]:
        """Yield an issue when a result answers a different operation."""
        if result.operation is not request.operation:
            yield ReasoningIssue(
                "operation_mismatch",
                f"result reports {result.operation.value!r} for a "
                f"{request.operation.value!r} request",
            )
        expected = _RESULT_TYPES[request.operation]
        if not isinstance(result, expected):
            yield ReasoningIssue(
                "result_type_mismatch",
                f"{type(result).__name__} cannot answer {request.operation.value!r} "
                f"(expected {expected.__name__})",
            )

    def _identifiers(self, result: OperationResult) -> Iterator[ReasoningIssue]:
        """Yield an issue for any id used twice within the response."""
        yield from _duplicates(
            "duplicate_finding_id", [item.finding_id for item in result.findings]
        )
        yield from _duplicates(
            "duplicate_recommendation_id",
            [item.recommendation_id for item in result.recommendations],
        )
        if isinstance(result, EnhanceResult):
            yield from _duplicates(
                "duplicate_change_id", [item.change_id for item in result.changes]
            )

    def _references(self, result: OperationResult) -> Iterator[ReasoningIssue]:
        """Yield an issue when a response points at a finding it does not contain."""
        known = {item.finding_id for item in result.findings}
        for recommendation in result.recommendations:
            for target in recommendation.addresses:
                if target not in known:
                    yield ReasoningIssue(
                        "unknown_finding_reference",
                        f"recommendation {recommendation.recommendation_id} addresses "
                        f"{target!r}, which is not a finding in this response",
                    )
        if not isinstance(result, EnhanceResult):
            return
        for change in result.changes:
            for target in change.addresses:
                if target not in known:
                    yield ReasoningIssue(
                        "unknown_finding_reference",
                        f"change {change.change_id} addresses {target!r}, which is not a "
                        "finding in this response",
                    )

    def _citations(
        self,
        result: OperationResult,
        material: SuppliedMaterial,
    ) -> Iterator[ReasoningIssue]:
        """Yield an issue for a citation of an item that was never supplied."""
        for citation in _citations(result):
            if citation.item_id not in material.item_ids:
                yield ReasoningIssue(
                    "fabricated_reference",
                    f"citation names context item {citation.item_id!r}, which the package "
                    "does not contain",
                )

    def _cited_identifiers(
        self,
        result: OperationResult,
        material: SuppliedMaterial,
    ) -> Iterator[ReasoningIssue]:
        """Yield an issue for an identifier that appears nowhere in the supplied material."""
        for citation in _citations(result):
            identifier = citation.identifier.strip()
            if identifier and not material.supplies(identifier):
                yield ReasoningIssue(
                    "fabricated_identifier",
                    f"citation of {citation.item_id!r} states identifier {identifier!r}, "
                    "which the supplied material does not contain",
                )
        for identifier, where in _claimed_identifiers(result):
            if identifier and not material.supplies(identifier):
                yield ReasoningIssue(
                    "fabricated_identifier",
                    f"{where} states identifier {identifier!r}, which the supplied material "
                    "does not contain",
                )

    def _uncertainty_carried(
        self,
        result: OperationResult,
        ledger: Sequence[UncertainIdentifier],
    ) -> Iterator[ReasoningIssue]:
        """Yield an issue when an unsettled identifier is dropped, promoted or narrowed."""
        reported = {entry.identifier: entry for entry in result.uncertainties}
        for expected in ledger:
            actual = reported.get(expected.identifier)
            if actual is None:
                yield ReasoningIssue(
                    "uncertainty_dropped",
                    f"{expected.identifier} is {expected.status.value} in the supplied "
                    "context but is absent from the response's uncertainties",
                )
                continue
            if actual.status is not expected.status:
                yield ReasoningIssue(
                    "uncertainty_status_changed",
                    f"{expected.identifier} is {expected.status.value} in the supplied "
                    f"context but the response reports it as {actual.status.value}",
                )
            missing = [
                candidate
                for candidate in expected.candidates
                if candidate not in actual.candidates
            ]
            if missing:
                yield ReasoningIssue(
                    "ambiguity_narrowed",
                    f"{expected.identifier} keeps {len(expected.candidates)} candidate(s) in "
                    f"the supplied context; the response omits {', '.join(missing)}",
                )
            invented = [
                candidate
                for candidate in actual.candidates
                if candidate not in expected.candidates
            ]
            if invented:
                yield ReasoningIssue(
                    "fabricated_candidate",
                    f"{expected.identifier} gains candidate(s) the supplied context does not "
                    f"list: {', '.join(invented)}",
                )
        known = {entry.identifier for entry in ledger}
        for entry in result.uncertainties:
            if entry.identifier not in known:
                yield ReasoningIssue(
                    "fabricated_uncertainty",
                    f"response reports {entry.identifier} as {entry.status.value}, but the "
                    "supplied context does not report it as unsettled",
                )

    def _uncertainty_not_promoted(
        self,
        result: OperationResult,
        ledger: Sequence[UncertainIdentifier],
    ) -> Iterator[ReasoningIssue]:
        """Yield an issue when an unsettled identifier is treated as established."""
        unsettled = {entry.identifier: entry for entry in ledger}
        if not unsettled:
            return
        for identifier, support, where in _supported_claims(result):
            entry = unsettled.get(identifier)
            if entry is not None and support is SupportLevel.SUPPORTED:
                yield ReasoningIssue(
                    "uncertainty_presented_as_fact",
                    f"{where} rests on {identifier}, which the supplied context reports as "
                    f"{entry.status.value}, yet declares support 'supported'",
                )
        for rule, where in _produced_rules(result):
            for mapping in rule.mitre:
                for identifier in (mapping.technique_id, mapping.tactic_id):
                    entry = unsettled.get(identifier.strip())
                    if identifier.strip() and entry is not None:
                        yield ReasoningIssue(
                            "unsettled_identifier_in_rule",
                            f"{where} maps to {identifier}, which the supplied context "
                            f"reports as {entry.status.value}",
                        )

    def _rule_output(
        self,
        result: OperationResult,
        request: ReasoningRequest,
        material: SuppliedMaterial,
    ) -> Iterator[ReasoningIssue]:
        """Yield an issue when the artefact an operation must produce is unusable."""
        if isinstance(result, EnhanceResult):
            yield from self._enhanced(result, request)
        if isinstance(result, GenerateResult):
            yield from self._generated(result)
        for rule, where in _produced_rules(result):
            for mapping in rule.mitre:
                for identifier in (mapping.technique_id, mapping.tactic_id):
                    if identifier.strip() and not material.supplies(identifier.strip()):
                        yield ReasoningIssue(
                            "fabricated_identifier",
                            f"{where} maps to {identifier!r}, which the supplied material "
                            "does not contain",
                        )

    def _enhanced(
        self,
        result: EnhanceResult,
        request: ReasoningRequest,
    ) -> Iterator[ReasoningIssue]:
        """Yield the issues of an enhancement's own artefacts."""
        if not result.changes:
            yield ReasoningIssue(
                "no_changes_accounted",
                "an enhanced rule was returned with no change accounted for",
            )
        supplied = _normalise(request.rule_context.query)
        stated = _normalise(result.original_rule.query)
        if supplied and stated and supplied != stated:
            yield ReasoningIssue(
                "original_rule_altered",
                "original_rule.query does not reproduce the query of the supplied rule",
            )
        if _normalise(result.enhanced_rule.query) == supplied and supplied:
            yield ReasoningIssue(
                "rule_unchanged",
                "the enhanced query is identical to the supplied query, yet changes were "
                "accounted for",
            )

    def _generated(self, result: GenerateResult) -> Iterator[ReasoningIssue]:
        """Yield the issues of a generation's own artefacts."""
        if not result.rationale:
            yield ReasoningIssue(
                "no_rationale",
                "a generated rule was returned with no authoring decision accounted for",
            )


def _citations(result: OperationResult) -> tuple[Evidence, ...]:
    """Return every citation a result carries, in document order."""
    citations: list[Evidence] = [
        citation for finding in result.findings for citation in finding.evidence
    ]
    if isinstance(result, EnhanceResult):
        citations.extend(
            citation for change in result.changes for citation in change.evidence
        )
    if isinstance(result, GenerateResult):
        citations.extend(
            citation for entry in result.rationale for citation in entry.evidence
        )
        citations.extend(
            citation for mapping in result.mappings for citation in mapping.evidence
        )
    return tuple(citations)


def _claimed_identifiers(result: OperationResult) -> Iterator[tuple[str, str]]:
    """Yield every identifier a result claims outside a citation, with where it appears."""
    if isinstance(result, GenerateResult):
        for mapping in result.mappings:
            for identifier in (mapping.technique_id, mapping.tactic_id):
                if identifier.strip():
                    yield identifier.strip(), f"mapping {mapping.technique_id or '-'}"


def _supported_claims(result: OperationResult) -> Iterator[tuple[str, SupportLevel, str]]:
    """Yield every ``(identifier, support, location)`` a result asserts."""
    for finding in result.findings:
        for citation in finding.evidence:
            if citation.identifier.strip():
                yield citation.identifier.strip(), finding.support, f"finding {finding.finding_id}"
    if isinstance(result, EnhanceResult):
        for change in result.changes:
            for citation in change.evidence:
                if citation.identifier.strip():
                    yield citation.identifier.strip(), change.support, f"change {change.change_id}"
    if isinstance(result, GenerateResult):
        for mapping in result.mappings:
            for identifier in (mapping.technique_id, mapping.tactic_id):
                if identifier.strip():
                    yield identifier.strip(), mapping.support, f"mapping {mapping.technique_id}"


def _produced_rules(result: OperationResult) -> Iterator[tuple[DetectionRuleDraft, str]]:
    """Yield every rule a result produced, with the field it came from."""
    if isinstance(result, EnhanceResult):
        yield result.enhanced_rule, "enhanced_rule"
    if isinstance(result, GenerateResult):
        yield result.generated_rule, "generated_rule"


def _duplicates(check: str, values: Sequence[str]) -> Iterator[ReasoningIssue]:
    """Yield an issue for every value used more than once."""
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    for value, count in counts.items():
        if count > 1:
            yield ReasoningIssue(check, f"{value!r} is used {count} times")


def _normalise(text: str) -> str:
    """Return text with runs of whitespace collapsed, for comparison only."""
    return _WHITESPACE.sub(" ", text).strip()


_RESULT_TYPES: Final[Mapping[ReasoningOperation, type[OperationResult]]] = MappingProxyType(
    {
        ReasoningOperation.ANALYZE: AnalyzeResult,
        ReasoningOperation.ENHANCE: EnhanceResult,
        ReasoningOperation.GENERATE: GenerateResult,
    }
)
"""Which result type answers which operation."""
