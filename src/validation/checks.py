"""The checks.

Six checkers, one per validation category. Each takes a result and the supplied
view and yields issues; none of them mutates anything, calls a provider, opens a
file or reaches the network.

Overlap with Stage-15 is deliberate where it concerns safety. Stage-15 validates
the response it just parsed; this layer validates whatever result reaches the
boundary, including one an application assembled itself, so a check that only
existed upstream would be a check a caller could route around. Where the two
agree, they agree independently — this module reads the context package and the
result directly rather than trusting an earlier verdict.

What is genuinely new here rather than restated: structural checking of the
typed object (Stage-15 checks the JSON document, before the object exists),
provenance agreement between a citation and the item it names, security scanning
of what the result *says*, and rule-shape coherence for a produced rule.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, fields
from typing import Final, final

from src.context.evidence import redact
from src.context.types import EvidenceStatus
from src.core.context_view import FENCE_BEGIN, FENCE_END
from src.core.models import (
    AnalyzeResult,
    DetectionRuleDraft,
    EnhanceResult,
    GenerateResult,
    OperationResult,
)
from src.core.output_format import spec_for
from src.core.types import (
    EvidenceSource,
    OutputLanguage,
    OutputRuleType,
    OutputSeverity,
    ReasoningOperation,
    SupportLevel,
    UncertaintyStatus,
)
from src.prompts.placeholders import find_placeholders

from .models import ValidationIssue
from .supplied import SuppliedContext, citations, texts
from .types import IssueSeverity, ValidationCode

_WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")
_URL: Final[re.Pattern[str]] = re.compile(r"https?://[^\s\"'<>)\]]+")

_RESULT_TYPES: Final[dict[ReasoningOperation, type[OperationResult]]] = {
    ReasoningOperation.ANALYZE: AnalyzeResult,
    ReasoningOperation.ENHANCE: EnhanceResult,
    ReasoningOperation.GENERATE: GenerateResult,
}
"""Which result type answers which operation."""

_LANGUAGES_FOR_TYPE: Final[dict[OutputRuleType, frozenset[OutputLanguage]]] = {
    OutputRuleType.EQL: frozenset({OutputLanguage.EQL}),
    OutputRuleType.ESQL: frozenset({OutputLanguage.ESQL}),
    OutputRuleType.QUERY: frozenset({OutputLanguage.KQL, OutputLanguage.LUCENE}),
    OutputRuleType.THRESHOLD: frozenset({OutputLanguage.KQL, OutputLanguage.LUCENE}),
    OutputRuleType.NEW_TERMS: frozenset({OutputLanguage.KQL, OutputLanguage.LUCENE}),
}
"""Which query languages each Elastic rule type can actually be written in.

An ``eql`` rule holding a KQL query is not a stylistic choice; it is a rule that
will not load.
"""

_RISK_BANDS: Final[dict[OutputSeverity, tuple[int, int]]] = {
    OutputSeverity.LOW: (0, 21),
    OutputSeverity.MEDIUM: (22, 47),
    OutputSeverity.HIGH: (48, 73),
    OutputSeverity.CRITICAL: (74, 100),
}
"""Elastic's conventional risk-score bands per severity.

A mismatch is reported as a warning, not an error: the pairing is a convention a
deployment may deliberately depart from, unlike the checks that guard against
fabrication.
"""


def _issue(
    code: ValidationCode,
    path: str,
    message: str,
    severity: IssueSeverity = IssueSeverity.ERROR,
) -> ValidationIssue:
    """Return one issue."""
    return ValidationIssue(code=code, severity=severity, path=path, message=message)


def _normalise(text: str) -> str:
    """Return text with runs of whitespace collapsed, for comparison only."""
    return _WHITESPACE.sub(" ", text).strip()


@final
@dataclass(frozen=True, slots=True)
class StructuralChecker:
    """Checks the result's own shape.

    Stage-15's schema validator runs against the JSON document, before any typed
    object exists. This runs against the object, so it also covers a result that
    reached the boundary without passing through the parser.
    """

    def check(
        self,
        result: OperationResult,
        supplied: SuppliedContext,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield the structural issues of one result."""
        yield from self._operation(result, operation)
        yield from self._declared_fields(result, operation)
        yield from self._ranges(result)
        yield from self._required_text(result)
        yield from self._identifiers(result)
        yield from self._references(result)
        yield from self._combinations(result)

    def _operation(
        self,
        result: OperationResult,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield an issue when the result does not answer the operation asked."""
        if result.operation is not operation:
            yield _issue(
                ValidationCode.OPERATION_MISMATCH,
                "operation",
                f"result reports {result.operation.value!r} for a {operation.value!r} request",
            )
        expected = _RESULT_TYPES[operation]
        if not isinstance(result, expected):
            yield _issue(
                ValidationCode.RESULT_TYPE_MISMATCH,
                "$",
                f"{type(result).__name__} cannot answer {operation.value!r}; "
                f"expected {expected.__name__}",
            )

    def _declared_fields(
        self,
        result: OperationResult,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield an issue when the result type and the operation's schema disagree.

        Guards against drift: if a field is added to one and not the other, the
        contract the model was shown stops matching the object built from it.
        """
        if not isinstance(result, _RESULT_TYPES[operation]):
            return
        declared = set(spec_for(operation).field_names())
        present = {item.name for item in fields(result)} - {"provenance"}
        for name in sorted(present - declared):
            yield _issue(
                ValidationCode.UNDECLARED_FIELD,
                name,
                f"result carries {name!r}, which the {operation.value} schema does not declare",
            )
        for name in sorted(declared - present):
            yield _issue(
                ValidationCode.MISSING_VALUE,
                name,
                f"the {operation.value} schema declares {name!r}, which the result lacks",
            )

    def _ranges(self, result: OperationResult) -> Iterator[ValidationIssue]:
        """Yield an issue for every number outside its permitted range."""
        if not 0.0 <= result.confidence <= 1.0:
            yield _issue(
                ValidationCode.OUT_OF_RANGE,
                "confidence",
                f"{result.confidence} is outside 0.0..1.0",
            )
        for index, finding in enumerate(result.findings):
            if not 0.0 <= finding.confidence <= 1.0:
                yield _issue(
                    ValidationCode.OUT_OF_RANGE,
                    f"findings[{index}].confidence",
                    f"{finding.confidence} is outside 0.0..1.0",
                )
        for path, rule in _produced_rules(result):
            if not 0 <= rule.risk_score <= 100:
                yield _issue(
                    ValidationCode.OUT_OF_RANGE,
                    f"{path}.risk_score",
                    f"{rule.risk_score} is outside 0..100",
                )

    def _required_text(self, result: OperationResult) -> Iterator[ValidationIssue]:
        """Yield an issue for a required string that is empty or spans lines."""
        required = {"summary": result.summary}
        for index, finding in enumerate(result.findings):
            required[f"findings[{index}].finding_id"] = finding.finding_id
            required[f"findings[{index}].statement"] = finding.statement
            required[f"findings[{index}].explanation"] = finding.explanation
        for index, item in enumerate(result.recommendations):
            required[f"recommendations[{index}].recommendation_id"] = item.recommendation_id
            required[f"recommendations[{index}].action"] = item.action
        for index, entry in enumerate(result.uncertainties):
            required[f"uncertainties[{index}].identifier"] = entry.identifier
            required[f"uncertainties[{index}].treatment"] = entry.treatment
        for path, rule in _produced_rules(result):
            required[f"{path}.title"] = rule.title
            required[f"{path}.query"] = rule.query
            required[f"{path}.investigation_guide"] = rule.investigation_guide
        for path, value in required.items():
            if not value.strip():
                yield _issue(ValidationCode.MISSING_VALUE, path, "required value is empty")
        for path, value in texts(result):
            if "\n" in value or "\r" in value:
                yield _issue(
                    ValidationCode.MULTILINE_STRING,
                    path,
                    "value spans several lines; the contract requires one",
                )

    def _identifiers(self, result: OperationResult) -> Iterator[ValidationIssue]:
        """Yield an issue for any identifier used twice within the result."""
        yield from _duplicates("findings", [item.finding_id for item in result.findings])
        yield from _duplicates(
            "recommendations", [item.recommendation_id for item in result.recommendations]
        )
        yield from _duplicates(
            "uncertainties", [item.identifier for item in result.uncertainties]
        )
        if isinstance(result, EnhanceResult):
            yield from _duplicates("changes", [item.change_id for item in result.changes])

    def _references(self, result: OperationResult) -> Iterator[ValidationIssue]:
        """Yield an issue when the result points at a finding it does not contain."""
        known = {item.finding_id for item in result.findings}
        for index, recommendation in enumerate(result.recommendations):
            for position, target in enumerate(recommendation.addresses):
                if target not in known:
                    yield _issue(
                        ValidationCode.UNKNOWN_REFERENCE,
                        f"recommendations[{index}].addresses[{position}]",
                        f"{target!r} is not a finding in this result",
                    )
        if not isinstance(result, EnhanceResult):
            return
        for index, change in enumerate(result.changes):
            for position, target in enumerate(change.addresses):
                if target not in known:
                    yield _issue(
                        ValidationCode.UNKNOWN_REFERENCE,
                        f"changes[{index}].addresses[{position}]",
                        f"{target!r} is not a finding in this result",
                    )

    def _combinations(self, result: OperationResult) -> Iterator[ValidationIssue]:
        """Yield an issue for a combination of values that cannot both be true."""
        for index, entry in enumerate(result.uncertainties):
            if entry.status is UncertaintyStatus.UNRESOLVED and entry.candidates:
                yield _issue(
                    ValidationCode.IMPOSSIBLE_COMBINATION,
                    f"uncertainties[{index}].candidates",
                    f"{entry.identifier} is unresolved yet lists "
                    f"{len(entry.candidates)} candidate(s)",
                )
            if entry.status is UncertaintyStatus.AMBIGUOUS and not entry.candidates:
                yield _issue(
                    ValidationCode.IMPOSSIBLE_COMBINATION,
                    f"uncertainties[{index}].candidates",
                    f"{entry.identifier} is ambiguous yet lists no candidate",
                )
        for index, finding in enumerate(result.findings):
            if finding.support is SupportLevel.UNSUPPORTED and finding.confidence > 0.5:
                yield _issue(
                    ValidationCode.IMPOSSIBLE_COMBINATION,
                    f"findings[{index}].confidence",
                    f"support is 'unsupported' yet confidence is {finding.confidence}",
                )


@final
@dataclass(frozen=True, slots=True)
class EvidenceChecker:
    """Checks that what the result cites was actually supplied."""

    def check(
        self,
        result: OperationResult,
        supplied: SuppliedContext,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield the evidence issues of one result."""
        for path, citation in citations(result):
            if not citation.item_id.strip():
                yield _issue(
                    ValidationCode.EMPTY_CITATION,
                    f"{path}.item_id",
                    "citation names no context item",
                )
            elif supplied.item(citation.item_id) is None:
                yield _issue(
                    ValidationCode.UNKNOWN_ITEM,
                    f"{path}.item_id",
                    f"{citation.item_id!r} is not an item of the supplied context package",
                )
            identifier = citation.identifier.strip()
            if identifier and not supplied.supplies(identifier):
                yield _issue(
                    ValidationCode.FABRICATED_IDENTIFIER,
                    f"{path}.identifier",
                    f"{identifier!r} does not occur in the supplied material",
                )
        yield from self._supported_claims(result)

    def _supported_claims(self, result: OperationResult) -> Iterator[ValidationIssue]:
        """Yield an issue for a claim that declares support but cites nothing."""
        for index, finding in enumerate(result.findings):
            if finding.support is SupportLevel.SUPPORTED and not finding.evidence:
                yield _issue(
                    ValidationCode.UNSUPPORTED_CLAIM,
                    f"findings[{index}].evidence",
                    "finding declares support 'supported' while citing nothing",
                )
        if isinstance(result, EnhanceResult):
            for index, change in enumerate(result.changes):
                if change.support is SupportLevel.SUPPORTED and not change.evidence:
                    yield _issue(
                        ValidationCode.UNSUPPORTED_CLAIM,
                        f"changes[{index}].evidence",
                        "change declares support 'supported' while citing nothing",
                    )
        if isinstance(result, GenerateResult):
            for index, mapping in enumerate(result.mappings):
                if mapping.support is SupportLevel.SUPPORTED and not mapping.evidence:
                    yield _issue(
                        ValidationCode.UNSUPPORTED_CLAIM,
                        f"mappings[{index}].evidence",
                        "mapping declares support 'supported' while citing nothing",
                    )


@final
@dataclass(frozen=True, slots=True)
class UncertaintyChecker:
    """Checks that unsettled identifiers survived reasoning unchanged."""

    def check(
        self,
        result: OperationResult,
        supplied: SuppliedContext,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield the uncertainty issues of one result."""
        reported = {entry.identifier: (index, entry) for index, entry in
                    enumerate(result.uncertainties)}
        for identifier, expected in supplied.ledger.items():
            found = reported.get(identifier)
            if found is None:
                yield _issue(
                    ValidationCode.UNCERTAINTY_DROPPED,
                    "uncertainties",
                    f"{identifier} is {expected.status.value} in the supplied context but the "
                    "result does not carry it",
                )
                continue
            index, actual = found
            if actual.status is not expected.status:
                yield _issue(
                    ValidationCode.UNCERTAINTY_STATUS_PROMOTED,
                    f"uncertainties[{index}].status",
                    f"{identifier} is {expected.status.value} in the supplied context but the "
                    f"result reports {actual.status.value}",
                )
            missing = [c for c in expected.candidates if c not in actual.candidates]
            if missing:
                yield _issue(
                    ValidationCode.AMBIGUITY_NARROWED,
                    f"uncertainties[{index}].candidates",
                    f"{identifier} keeps {len(expected.candidates)} candidate(s) in the supplied "
                    f"context; the result omits {', '.join(missing)}",
                )
            invented = [c for c in actual.candidates if c not in expected.candidates]
            if invented:
                yield _issue(
                    ValidationCode.FABRICATED_CANDIDATE,
                    f"uncertainties[{index}].candidates",
                    f"{identifier} gains candidate(s) the supplied context does not list: "
                    f"{', '.join(invented)}",
                )
        for index, entry in enumerate(result.uncertainties):
            if entry.identifier not in supplied.ledger:
                yield _issue(
                    ValidationCode.FABRICATED_UNCERTAINTY,
                    f"uncertainties[{index}].identifier",
                    f"result reports {entry.identifier} as {entry.status.value}, but the "
                    "supplied context does not report it as unsettled",
                )
        yield from self._not_promoted(result, supplied)

    def _not_promoted(
        self,
        result: OperationResult,
        supplied: SuppliedContext,
    ) -> Iterator[ValidationIssue]:
        """Yield an issue when an unsettled identifier is treated as established."""
        if not supplied.ledger:
            return
        for path, citation in citations(result):
            identifier = citation.identifier.strip()
            entry = supplied.ledger.get(identifier)
            if entry is None:
                continue
            support = _support_of(result, path)
            if support is SupportLevel.SUPPORTED:
                yield _issue(
                    ValidationCode.UNCERTAINTY_PRESENTED_AS_FACT,
                    path,
                    f"the claim rests on {identifier}, which the supplied context reports as "
                    f"{entry.status.value}, yet declares support 'supported'",
                )
        for path, rule in _produced_rules(result):
            for index, mapping in enumerate(rule.mitre):
                for name, identifier in (
                    ("technique_id", mapping.technique_id),
                    ("tactic_id", mapping.tactic_id),
                ):
                    entry = supplied.ledger.get(identifier.strip())
                    if identifier.strip() and entry is not None:
                        yield _issue(
                            ValidationCode.UNSETTLED_IDENTIFIER_IN_RULE,
                            f"{path}.mitre[{index}].{name}",
                            f"the rule maps to {identifier}, which the supplied context reports "
                            f"as {entry.status.value}",
                        )


@final
@dataclass(frozen=True, slots=True)
class RuleIntegrityChecker:
    """Checks that a produced or preserved rule is usable and honestly described."""

    def check(
        self,
        result: OperationResult,
        supplied: SuppliedContext,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield the rule integrity issues of one result."""
        for path, rule in _produced_rules(result):
            yield from self._shape(path, rule)
            yield from self._mappings(path, rule, supplied)
        if isinstance(result, EnhanceResult):
            yield from self._enhanced(result, supplied)
        if isinstance(result, GenerateResult) and not result.rationale:
            yield _issue(
                ValidationCode.NO_RATIONALE,
                "rationale",
                "a generated rule was returned with no authoring decision accounted for",
            )

    def _shape(self, path: str, rule: DetectionRuleDraft) -> Iterator[ValidationIssue]:
        """Yield an issue when a rule could not be deployed as described."""
        allowed = _LANGUAGES_FOR_TYPE[rule.rule_type]
        if rule.language not in allowed:
            yield _issue(
                ValidationCode.LANGUAGE_TYPE_MISMATCH,
                f"{path}.language",
                f"rule_type {rule.rule_type.value!r} cannot carry a "
                f"{rule.language.value!r} query; expected "
                f"{' or '.join(sorted(item.value for item in allowed))}",
            )
        if not rule.query.strip():
            yield _issue(
                ValidationCode.INCOMPLETE_RULE, f"{path}.query", "rule carries no query"
            )
        if not rule.investigation_guide.strip():
            yield _issue(
                ValidationCode.INCOMPLETE_RULE,
                f"{path}.investigation_guide",
                "rule carries no investigation guidance",
            )
        low, high = _RISK_BANDS[rule.severity]
        if not low <= rule.risk_score <= high:
            yield _issue(
                ValidationCode.RISK_SEVERITY_MISMATCH,
                f"{path}.risk_score",
                f"severity {rule.severity.value!r} conventionally spans {low}..{high}, "
                f"but the risk score is {rule.risk_score}",
                IssueSeverity.WARNING,
            )

    def _mappings(
        self,
        path: str,
        rule: DetectionRuleDraft,
        supplied: SuppliedContext,
    ) -> Iterator[ValidationIssue]:
        """Yield an issue for an ATT&CK identifier the material never supplied."""
        for index, mapping in enumerate(rule.mitre):
            for name, identifier in (
                ("technique_id", mapping.technique_id),
                ("tactic_id", mapping.tactic_id),
            ):
                value = identifier.strip()
                if value and not supplied.supplies(value):
                    yield _issue(
                        ValidationCode.FABRICATED_MAPPING,
                        f"{path}.mitre[{index}].{name}",
                        f"the rule maps to {value!r}, which the supplied material does not "
                        "contain",
                    )

    def _enhanced(
        self,
        result: EnhanceResult,
        supplied: SuppliedContext,
    ) -> Iterator[ValidationIssue]:
        """Yield the issues particular to an enhancement."""
        if not result.changes:
            yield _issue(
                ValidationCode.NO_CHANGES_ACCOUNTED,
                "changes",
                "an enhanced rule was returned with no change accounted for",
            )
        stated = _normalise(result.original_rule.query)
        supplied_query = _normalise(supplied.rule_query)
        if supplied_query and stated and stated != supplied_query:
            yield _issue(
                ValidationCode.ORIGINAL_RULE_ALTERED,
                "original_rule.query",
                "original_rule.query does not reproduce the query the package states for the "
                "rule under consideration",
            )
        if stated and stated == _normalise(result.enhanced_rule.query):
            yield _issue(
                ValidationCode.RULE_UNCHANGED,
                "enhanced_rule.query",
                "the enhanced query is identical to the original, yet changes were accounted for",
            )


@final
@dataclass(frozen=True, slots=True)
class SecurityChecker:
    """Checks what the result carries out of the engine.

    Scans the result's own text. The context layer redacts what goes *in*;
    nothing before this point looks at what comes back, and a model can echo
    material it was shown.
    """

    def check(
        self,
        result: OperationResult,
        supplied: SuppliedContext,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield the security issues of one result."""
        for path, value in texts(result):
            if not value:
                continue
            _, fired = redact(value)
            if fired:
                yield _issue(
                    ValidationCode.CREDENTIAL_IN_RESULT,
                    path,
                    f"value carries a credential shape ({', '.join(fired)})",
                )
            if find_placeholders(value):
                yield _issue(
                    ValidationCode.TEMPLATE_ARTIFACT,
                    path,
                    "value carries a prompt template placeholder",
                )
            if FENCE_BEGIN in value or FENCE_END in value:
                yield _issue(
                    ValidationCode.FENCE_ARTIFACT,
                    path,
                    "value carries an untrusted-input fence marker from the prompt",
                )
            for url in _URL.findall(value):
                if url not in supplied.text:
                    yield _issue(
                        ValidationCode.FABRICATED_REFERENCE,
                        path,
                        f"value cites {url!r}, which the supplied material does not contain",
                    )


@final
@dataclass(frozen=True, slots=True)
class ProvenanceChecker:
    """Checks that every citation still traces back to what it names."""

    def check(
        self,
        result: OperationResult,
        supplied: SuppliedContext,
        operation: ReasoningOperation,
    ) -> Iterator[ValidationIssue]:
        """Yield the provenance issues of one result."""
        for path, citation in citations(result):
            item = supplied.item(citation.item_id)
            if item is None:
                continue  # the evidence check already reported it
            actual = item.source
            declared = citation.source
            if actual is not None and declared is not EvidenceSource.from_knowledge_source(actual):
                yield _issue(
                    ValidationCode.CITATION_SOURCE_MISMATCH,
                    f"{path}.source",
                    f"citation says {declared.value!r} but {citation.item_id} came from "
                    f"{actual.value!r}",
                )
            if item.provenance.is_retrieved and not item.provenance.dataset_location:
                yield _issue(
                    ValidationCode.CITATION_NOT_TRACEABLE,
                    f"{path}.item_id",
                    f"{citation.item_id} carries no dataset location to trace back to",
                )
            if item.evidence_status in _UNSETTLED_STATUSES:
                identifier = item.metadata.get("identifier", "").strip()
                if identifier and identifier not in {
                    entry.identifier for entry in result.uncertainties
                }:
                    yield _issue(
                        ValidationCode.EVIDENCE_STATUS_NOT_PRESERVED,
                        f"{path}.item_id",
                        f"{citation.item_id} is {item.evidence_status.value} in the context, but "
                        f"{identifier} is absent from the result's uncertainties",
                    )


_UNSETTLED_STATUSES: Final[frozenset[EvidenceStatus]] = frozenset(
    {EvidenceStatus.UNRESOLVED, EvidenceStatus.AMBIGUOUS}
)


def _produced_rules(result: OperationResult) -> Iterator[tuple[str, DetectionRuleDraft]]:
    """Yield every rule a result produced, with the field it came from."""
    if isinstance(result, EnhanceResult):
        yield "enhanced_rule", result.enhanced_rule
    if isinstance(result, GenerateResult):
        yield "generated_rule", result.generated_rule


def _support_of(result: OperationResult, path: str) -> SupportLevel | None:
    """Return the support level of the claim a citation path belongs to."""
    index = _leading_index(path)
    if index is None:
        return None
    if path.startswith("findings[") and index < len(result.findings):
        return result.findings[index].support
    if isinstance(result, EnhanceResult) and path.startswith("changes["):
        return result.changes[index].support if index < len(result.changes) else None
    if isinstance(result, GenerateResult) and path.startswith("mappings["):
        return result.mappings[index].support if index < len(result.mappings) else None
    return None


def _leading_index(path: str) -> int | None:
    """Return the first bracketed index of a path, when it has one."""
    match = re.search(r"\[(\d+)\]", path)
    return int(match.group(1)) if match else None


def _duplicates(prefix: str, values: Sequence[str]) -> Iterator[ValidationIssue]:
    """Yield an issue for every identifier used more than once."""
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    for value in sorted(name for name, count in counts.items() if count > 1):
        yield _issue(
            ValidationCode.DUPLICATE_ID,
            prefix,
            f"{value!r} is used {counts[value]} times",
        )
