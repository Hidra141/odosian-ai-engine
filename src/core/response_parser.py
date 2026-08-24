"""Response parsing.

Turns a provider response into a typed reasoning result, or fails.

Three steps, in this order and no other:

1. **Decode.** Stage-07's ``parse_json_object`` reads the body. It is strict by
   design — no fence stripping, no bracket closing, no trailing comma removal,
   no extraction of the first object it can find in surrounding prose — and this
   layer adds no repair of its own. A body that does not decode raises Stage-07's
   own ``LLMInvalidJSONError``.
2. **Check the structure.** The operation's schema is applied to the decoded
   document. Every fault is collected and raised together as a
   :class:`~src.core.exceptions.ResponseSchemaError`.
3. **Build.** Only then are the typed models constructed. Because construction
   happens after the check rather than during it, no conversion here has to
   guess what to do with a value of the wrong shape: there are none left.

The models are built in the response's own order. Nothing is sorted,
deduplicated, defaulted or filled in, so the result is exactly what the model
returned, expressed in types.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, cast, final

from src.llm.json_parser import parse_json_object
from src.llm.response import LLMResponse
from src.llm.types import JSONObject, JSONValue

from .exceptions import ResponseSchemaError
from .models import (
    AnalyzeResult,
    DetectionRuleDraft,
    EnhanceResult,
    EvasionRisk,
    Evidence,
    Finding,
    GenerateResult,
    MappingClaim,
    MitreMapping,
    OperationResult,
    OriginalRule,
    RationaleEntry,
    ReasoningProvenance,
    Recommendation,
    RuleChange,
    Uncertainty,
)
from .output_format import spec_for
from .schema import SchemaValidator
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

_EMPTY: Final[Mapping[str, str]] = MappingProxyType({})


@final
@dataclass(frozen=True, slots=True)
class ResponseParser:
    """Builds a typed result from a provider response."""

    def parse(
        self,
        operation: ReasoningOperation,
        response: LLMResponse,
    ) -> OperationResult:
        """Decode, check and convert one response."""
        document = parse_json_object(
            response.text,
            provider=response.provider,
            model=response.model,
        )
        self.check(operation, document)
        provenance = ReasoningProvenance.from_response(operation, response)
        return self.build(operation, document, provenance)

    def check(self, operation: ReasoningOperation, document: JSONObject) -> None:
        """Raise when a decoded document does not match the operation's schema."""
        issues = SchemaValidator(spec_for(operation)).validate(document)
        if issues:
            raise ResponseSchemaError(operation.value, [str(issue) for issue in issues])

    def build(
        self,
        operation: ReasoningOperation,
        document: JSONObject,
        provenance: ReasoningProvenance,
    ) -> OperationResult:
        """Convert a checked document into the result type of its operation."""
        common = {
            "operation": operation,
            "summary": _text(document, "summary"),
            "findings": tuple(_finding(entry) for entry in _objects(document, "findings")),
            "recommendations": tuple(
                _recommendation(entry) for entry in _objects(document, "recommendations")
            ),
            "confidence": _number(document, "confidence"),
            "metadata": _string_map(document, "metadata"),
            "uncertainties": tuple(
                _uncertainty(entry) for entry in _objects(document, "uncertainties")
            ),
            "provenance": provenance,
        }
        match operation:
            case ReasoningOperation.ANALYZE:
                return AnalyzeResult(
                    **common,  # type: ignore[arg-type]
                    score=_integer(document, "score"),
                    fp_risk=FalsePositiveRisk(_text(document, "fp_risk")),
                    strengths=_strings(document, "strengths"),
                    weaknesses=_strings(document, "weaknesses"),
                    evasion_risks=tuple(
                        _evasion_risk(entry) for entry in _objects(document, "evasion_risks")
                    ),
                    mappings=tuple(_mapping(entry) for entry in _objects(document, "mappings")),
                )
            case ReasoningOperation.ENHANCE:
                return EnhanceResult(
                    **common,  # type: ignore[arg-type]
                    original_rule=_original_rule(_object(document, "original_rule")),
                    enhanced_rule=_rule(_object(document, "enhanced_rule")),
                    changes=tuple(_change(entry) for entry in _objects(document, "changes")),
                )
            case ReasoningOperation.GENERATE:
                return GenerateResult(
                    **common,  # type: ignore[arg-type]
                    generated_rule=_rule(_object(document, "generated_rule")),
                    rationale=tuple(
                        _rationale(entry) for entry in _objects(document, "rationale")
                    ),
                    mappings=tuple(_mapping(entry) for entry in _objects(document, "mappings")),
                    score=_integer(document, "score"),
                    notes=_text(document, "notes"),
                )


def _evasion_risk(entry: JSONObject) -> EvasionRisk:
    """Build one evasion route."""
    return EvasionRisk(
        technique=_text(entry, "technique"),
        description=_text(entry, "description"),
        mitigation=_text(entry, "mitigation"),
    )


def _finding(entry: JSONObject) -> Finding:
    """Build one finding."""
    return Finding(
        finding_id=_text(entry, "finding_id"),
        category=FindingCategory(_text(entry, "category")),
        severity=ImportanceLevel(_text(entry, "severity")),
        statement=_text(entry, "statement"),
        explanation=_text(entry, "explanation"),
        support=SupportLevel(_text(entry, "support")),
        evidence=tuple(_evidence(item) for item in _objects(entry, "evidence")),
        confidence=_number(entry, "confidence"),
    )


def _recommendation(entry: JSONObject) -> Recommendation:
    """Build one recommendation."""
    return Recommendation(
        recommendation_id=_text(entry, "recommendation_id"),
        category=FindingCategory(_text(entry, "category")),
        priority=ImportanceLevel(_text(entry, "priority")),
        action=_text(entry, "action"),
        rationale=_text(entry, "rationale"),
        addresses=_strings(entry, "addresses"),
        support=SupportLevel(_text(entry, "support")),
        code_snippet=_text(entry, "code_snippet"),
    )


def _evidence(entry: JSONObject) -> Evidence:
    """Build one citation."""
    raw_id = _text(entry, "item_id")
    if raw_id.startswith("[") and raw_id.endswith("]"):
        raw_id = raw_id[1:-1]
    return Evidence(
        item_id=raw_id,
        source=EvidenceSource(_text(entry, "source")),
        identifier=_text(entry, "identifier"),
        detail=_text(entry, "detail"),
    )


def _uncertainty(entry: JSONObject) -> Uncertainty:
    """Build one uncertainty entry."""
    return Uncertainty(
        identifier=_text(entry, "identifier"),
        status=UncertaintyStatus(_text(entry, "status")),
        candidates=_strings(entry, "candidates"),
        treatment=_text(entry, "treatment"),
    )


def _rule(entry: JSONObject) -> DetectionRuleDraft:
    """Build a produced rule."""
    return DetectionRuleDraft(
        title=_text(entry, "title"),
        description=_text(entry, "description"),
        rule_type=OutputRuleType(_text(entry, "rule_type")),
        language=OutputLanguage(_text(entry, "language")),
        query=_text(entry, "query"),
        severity=OutputSeverity(_text(entry, "severity")),
        risk_score=_integer(entry, "risk_score"),
        index_patterns=_strings(entry, "index_patterns"),
        false_positives=_strings(entry, "false_positives"),
        investigation_guide=_text(entry, "investigation_guide"),
        mitre=tuple(_mitre(item) for item in _objects(entry, "mitre")),
        tags=_strings(entry, "tags"),
    )


def _mitre(entry: JSONObject) -> MitreMapping:
    """Build one ATT&CK mapping of a produced rule."""
    return MitreMapping(
        tactic_id=_text(entry, "tactic_id"),
        technique_id=_text(entry, "technique_id"),
        tactic_name=_text(entry, "tactic_name"),
        technique_name=_text(entry, "technique_name"),
        confidence=_number(entry, "confidence"),
        parent_technique_id=_text(entry, "parent_technique_id"),
        parent_technique_name=_text(entry, "parent_technique_name"),
    )


def _original_rule(entry: JSONObject) -> OriginalRule:
    """Build the record of the rule as supplied."""
    return OriginalRule(
        identifier=_text(entry, "identifier"),
        title=_text(entry, "title"),
        language=_text(entry, "language"),
        query=_text(entry, "query"),
    )


def _change(entry: JSONObject) -> RuleChange:
    """Build one accounted change."""
    return RuleChange(
        change_id=_text(entry, "change_id"),
        category=ChangeCategory(_text(entry, "category")),
        before=_text(entry, "before"),
        after=_text(entry, "after"),
        rationale=_text(entry, "rationale"),
        addresses=_strings(entry, "addresses"),
        evidence=tuple(_evidence(item) for item in _objects(entry, "evidence")),
        support=SupportLevel(_text(entry, "support")),
    )


def _rationale(entry: JSONObject) -> RationaleEntry:
    """Build one authoring decision."""
    return RationaleEntry(
        aspect=RationaleAspect(_text(entry, "aspect")),
        statement=_text(entry, "statement"),
        rationale=_text(entry, "rationale"),
        evidence=tuple(_evidence(item) for item in _objects(entry, "evidence")),
    )


def _mapping(entry: JSONObject) -> MappingClaim:
    """Build one claimed ATT&CK mapping."""
    return MappingClaim(
        tactic_id=_text(entry, "tactic_id"),
        technique_id=_text(entry, "technique_id"),
        support=SupportLevel(_text(entry, "support")),
        evidence=tuple(_evidence(item) for item in _objects(entry, "evidence")),
        tactic_name=_text(entry, "tactic_name"),
        technique_name=_text(entry, "technique_name"),
        confidence=_number(entry, "confidence"),
        parent_technique_id=_text(entry, "parent_technique_id"),
        parent_technique_name=_text(entry, "parent_technique_name"),
    )


def _text(entry: JSONObject, key: str) -> str:
    """Return a string field of a checked document."""
    return cast(str, entry[key])


def _number(entry: JSONObject, key: str) -> float:
    """Return a numeric field of a checked document."""
    return float(cast(float, entry[key]))


def _integer(entry: JSONObject, key: str) -> int:
    """Return an integer field of a checked document."""
    return int(cast(int, entry[key]))


def _strings(entry: JSONObject, key: str) -> tuple[str, ...]:
    """Return a string array field of a checked document."""
    return tuple(cast(Sequence[str], entry[key]))


def _object(entry: JSONObject, key: str) -> JSONObject:
    """Return an object field of a checked document."""
    return cast(JSONObject, entry[key])


def _objects(entry: JSONObject, key: str) -> tuple[JSONObject, ...]:
    """Return an object array field of a checked document."""
    return tuple(cast(Sequence[JSONObject], entry[key]))


def _string_map(entry: JSONObject, key: str) -> Mapping[str, str]:
    """Return a string map field of a checked document, frozen against mutation."""
    value = cast(Mapping[str, str], entry[key])
    return MappingProxyType(dict(value)) if value else _EMPTY


def decode(response: LLMResponse) -> JSONObject:
    """Return the response body decoded as a JSON object.

    Offered so a caller can inspect what a provider returned without building a
    result from it. Applies no repair, exactly as ``parse_json_object`` does not.
    """
    return parse_json_object(response.text, provider=response.provider, model=response.model)


def as_json(value: JSONValue) -> JSONObject:
    """Return a JSON value narrowed to an object."""
    return cast(JSONObject, value)
