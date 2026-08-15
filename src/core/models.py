"""Reasoning models.

The typed requests the engine accepts and the typed results it returns.

A request preserves what it was asked about: the operation, the rule, and the
context package the earlier stages assembled for it. Nothing is copied out of
the package into a looser form, so a result can always be traced back to the
evidence that produced it.

A result is the parsed, validated response and nothing more. It carries no
timestamp, no generated identifier and no duration, because two identical runs
must produce two identical results. What varies between runs — how long the
provider took — stays on the :class:`~src.llm.response.LLMResponse` and is not
copied here.

Ordering is the response's own order throughout. Findings appear as the model
listed them; uncertainties appear as it listed them. Nothing is sorted,
deduplicated or re-ranked.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from src.context.models import ContextPackage, RuleContext
from src.llm.response import LLMResponse, TokenUsage
from src.llm.types import FinishReason
from src.parser.types import RuleLanguage

from .exceptions import InvalidReasoningRequestError
from .types import (
    ChangeCategory,
    EvidenceSource,
    FalsePositiveRisk,
    FindingCategory,
    ImportanceLevel,
    OutputLanguage,
    OutputRuleType,
    OutputSeverity,
    RationaleAspect,
    ReasoningOperation,
    SupportLevel,
    UncertaintyStatus,
)


@dataclass(frozen=True, slots=True)
class ReasoningRequest:
    """A request to run one operation over one context package.

    The rule is held separately from the package even though the package
    carries one, because the generate operation is asked about a requirement
    that no rule yet satisfies. Leaving the rule unset takes the package's own.
    """

    operation: ReasoningOperation
    package: ContextPackage
    rule: RuleContext | None = None

    @property
    def rule_context(self) -> RuleContext:
        """Return the rule under consideration."""
        return self.rule if self.rule is not None else self.package.rule_context

    def validate(self) -> None:
        """Raise when the request cannot be executed as stated."""
        package_operation = ReasoningOperation.from_context(self.package.operation)
        if package_operation is not self.operation:
            raise InvalidReasoningRequestError(
                f"operation is {self.operation.value!r} but the context package was built "
                f"for {package_operation.value!r}"
            )
        if self.rule_context.is_empty:
            subject = (
                "a detection requirement"
                if self.operation is ReasoningOperation.GENERATE
                else "a rule"
            )
            raise InvalidReasoningRequestError(
                f"operation {self.operation.value!r} needs {subject}, and neither the request "
                "nor the context package supplies one"
            )


@dataclass(frozen=True, slots=True)
class AnalyzeRequest:
    """A request to assess an existing rule."""

    package: ContextPackage
    rule: RuleContext | None = None

    @property
    def operation(self) -> ReasoningOperation:
        """Return the operation this request performs."""
        return ReasoningOperation.ANALYZE

    def as_reasoning_request(self) -> ReasoningRequest:
        """Return the operation-neutral form of this request."""
        return ReasoningRequest(self.operation, self.package, self.rule)


@dataclass(frozen=True, slots=True)
class EnhanceRequest:
    """A request to improve an existing rule."""

    package: ContextPackage
    rule: RuleContext | None = None

    @property
    def operation(self) -> ReasoningOperation:
        """Return the operation this request performs."""
        return ReasoningOperation.ENHANCE

    def as_reasoning_request(self) -> ReasoningRequest:
        """Return the operation-neutral form of this request."""
        return ReasoningRequest(self.operation, self.package, self.rule)


@dataclass(frozen=True, slots=True)
class GenerateRequest:
    """A request to write a rule for a stated requirement.

    ``requirement`` is the natural-language description of what is to be
    detected. It is supplied here when the package's rule context does not
    already carry it.
    """

    package: ContextPackage
    requirement: str = ""
    rule: RuleContext | None = None

    @property
    def operation(self) -> ReasoningOperation:
        """Return the operation this request performs."""
        return ReasoningOperation.GENERATE

    def as_reasoning_request(self) -> ReasoningRequest:
        """Return the operation-neutral form of this request."""
        rule = self.rule
        if rule is None and self.requirement.strip():
            rule = RuleContext(raw_text=self.requirement)
        return ReasoningRequest(self.operation, self.package, rule)


@dataclass(frozen=True, slots=True)
class Evidence:
    """A citation of one supplied context item."""

    item_id: str
    source: EvidenceSource
    identifier: str
    detail: str


@dataclass(frozen=True, slots=True)
class Uncertainty:
    """An identifier the supplied context could not settle, carried forward."""

    identifier: str
    status: UncertaintyStatus
    candidates: tuple[str, ...]
    treatment: str

    @property
    def is_ambiguous(self) -> bool:
        """Return whether several candidates answer to this identifier."""
        return self.status is UncertaintyStatus.AMBIGUOUS


@dataclass(frozen=True, slots=True)
class Finding:
    """An observation about the rule as it currently stands."""

    finding_id: str
    category: FindingCategory
    severity: ImportanceLevel
    statement: str
    explanation: str
    support: SupportLevel
    evidence: tuple[Evidence, ...]
    confidence: float


@dataclass(frozen=True, slots=True)
class Recommendation:
    """A proposed change to the rule."""

    recommendation_id: str
    category: FindingCategory
    priority: ImportanceLevel
    action: str
    rationale: str
    addresses: tuple[str, ...]
    support: SupportLevel
    code_snippet: str = ""


@dataclass(frozen=True, slots=True)
class MitreMapping:
    """One ATT&CK mapping a produced rule declares.

    The names sit beside the identifiers rather than being resolved later. They
    are copied from the supplied material, which is what makes an invented name
    detectable in the same way an invented identifier is — by not occurring in
    what was supplied. An empty name means the material carried the identifier
    without naming it: a real answer, not a gap to fill.
    """

    tactic_id: str
    technique_id: str
    tactic_name: str = ""
    technique_name: str = ""
    confidence: float = 0.0


@dataclass(frozen=True, slots=True)
class DetectionRuleDraft:
    """A complete detection rule the engine produced."""

    title: str
    description: str
    rule_type: OutputRuleType
    language: OutputLanguage
    query: str
    severity: OutputSeverity
    risk_score: int
    index_patterns: tuple[str, ...]
    false_positives: tuple[str, ...]
    investigation_guide: str
    mitre: tuple[MitreMapping, ...]
    tags: tuple[str, ...] = ()

    @property
    def parser_language(self) -> RuleLanguage:
        """Return the language in Stage-08's neutral vocabulary."""
        return RuleLanguage.from_value(self.language.value)


@dataclass(frozen=True, slots=True)
class OriginalRule:
    """The rule as it was supplied to an enhance operation."""

    identifier: str
    title: str
    language: str
    query: str


@dataclass(frozen=True, slots=True)
class RuleChange:
    """One change made to the original rule, with its justification."""

    change_id: str
    category: ChangeCategory
    before: str
    after: str
    rationale: str
    addresses: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    support: SupportLevel


@dataclass(frozen=True, slots=True)
class RationaleEntry:
    """One authoring decision behind a generated rule."""

    aspect: RationaleAspect
    statement: str
    rationale: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class MappingClaim:
    """One ATT&CK mapping claimed for a rule, with the material establishing it.

    Carried by an analysis as well as by a generation: an assessment states what
    the rule maps to, and states it with the same evidence and the same degree
    of support as any other claim.
    """

    tactic_id: str
    technique_id: str
    support: SupportLevel
    evidence: tuple[Evidence, ...]
    tactic_name: str = ""
    technique_name: str = ""
    confidence: float = 0.0


@dataclass(frozen=True, slots=True)
class ReasoningProvenance:
    """Where a result came from.

    Carries the response fields that describe the call rather than its content.
    The duration is deliberately absent: it varies between identical runs, and a
    result that varies is a result that cannot be compared.
    """

    operation: ReasoningOperation
    provider: str
    model: str
    finish_reason: FinishReason
    usage: TokenUsage

    @classmethod
    def from_response(
        cls,
        operation: ReasoningOperation,
        response: LLMResponse,
    ) -> ReasoningProvenance:
        """Build the provenance of a result from the response that produced it."""
        return cls(
            operation=operation,
            provider=response.provider,
            model=response.model,
            finish_reason=response.finish_reason,
            usage=response.usage,
        )


@dataclass(frozen=True, slots=True)
class ReasoningResult:
    """The part of a result every operation produces."""

    operation: ReasoningOperation
    summary: str
    findings: tuple[Finding, ...]
    recommendations: tuple[Recommendation, ...]
    confidence: float
    metadata: Mapping[str, str]
    uncertainties: tuple[Uncertainty, ...]
    provenance: ReasoningProvenance

    @property
    def has_uncertainty(self) -> bool:
        """Return whether the supplied context left anything unsettled."""
        return bool(self.uncertainties)

    def finding(self, finding_id: str) -> Finding | None:
        """Return one finding by its id."""
        for item in self.findings:
            if item.finding_id == finding_id:
                return item
        return None

    def cited_item_ids(self) -> tuple[str, ...]:
        """Return every context item id the result cites, in first-seen order."""
        seen: list[str] = []
        for citation in self._citations():
            if citation.item_id not in seen:
                seen.append(citation.item_id)
        return tuple(seen)

    def _citations(self) -> tuple[Evidence, ...]:
        """Return every citation the result carries, in document order."""
        return tuple(item for finding in self.findings for item in finding.evidence)


@dataclass(frozen=True, slots=True)
class AnalyzeResult(ReasoningResult):
    """The assessment of an existing rule.

    ``score`` and ``confidence`` answer different questions and are never
    interchangeable: the score judges the rule, while the inherited confidence
    reports how well the supplied context supported the judging. A thin context
    lowers confidence without flattering the rule.
    """

    score: int = 0
    fp_risk: FalsePositiveRisk = FalsePositiveRisk.MEDIUM
    strengths: tuple[str, ...] = ()
    evasion_risks: tuple[str, ...] = ()
    mappings: tuple[MappingClaim, ...] = ()

    def _citations(self) -> tuple[Evidence, ...]:
        """Return the citations of the findings and of every mapping claimed.

        The base method is called explicitly, for the reason given on
        :meth:`EnhanceResult._citations`.
        """
        return (
            *ReasoningResult._citations(self),
            *(item for mapping in self.mappings for item in mapping.evidence),
        )


@dataclass(frozen=True, slots=True)
class EnhanceResult(ReasoningResult):
    """An improved rule, with the weaknesses it answers and every change accounted for."""

    original_rule: OriginalRule
    enhanced_rule: DetectionRuleDraft
    changes: tuple[RuleChange, ...]

    def _citations(self) -> tuple[Evidence, ...]:
        """Return the citations of the findings and of every change.

        The base method is called explicitly rather than through ``super()``.
        ``dataclass(slots=True)`` builds a replacement class object, which
        leaves the ``__class__`` cell that zero-argument ``super()`` reads
        pointing at the class it replaced, and the call fails at runtime.
        """
        return (
            *ReasoningResult._citations(self),
            *(item for change in self.changes for item in change.evidence),
        )


@dataclass(frozen=True, slots=True)
class GenerateResult(ReasoningResult):
    """A rule written for a stated requirement, with the reasoning behind it."""

    generated_rule: DetectionRuleDraft
    rationale: tuple[RationaleEntry, ...]
    mappings: tuple[MappingClaim, ...]
    score: int = 0

    def _citations(self) -> tuple[Evidence, ...]:
        """Return the citations of the findings, the rationale and the mappings.

        The base method is called explicitly, for the reason given on
        :meth:`EnhanceResult._citations`.
        """
        return (
            *ReasoningResult._citations(self),
            *(item for entry in self.rationale for item in entry.evidence),
            *(item for mapping in self.mappings for item in mapping.evidence),
        )


type OperationResult = AnalyzeResult | EnhanceResult | GenerateResult
"""The result type of any one operation."""
