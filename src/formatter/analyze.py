"""The analyze contract.

An assessment rendered as ``01-analyze.jsonc`` states it.

Two fields are not copied but decided here. ``rating`` follows from the score by
the frozen band table, never from the model. ``outputQuery`` is the empty string
the contract demonstrates, because an analysis reads a rule and does not rewrite
it — the field exists so the record has the same shape as one that did.

Everything else is the validated result, renamed.
"""

from __future__ import annotations

from typing import Any

from src.core.models import AnalyzeResult

from .exceptions import OperationMismatchError
from .normalize import attack_mapping, finding_category, fp_risk, priority
from .rating import rating_from_score
from .runtime import RuntimeContext

ANALYSIS_TYPE = "analyze"
"""What the record calls itself.

``02-post-enhance.jsonc`` re-scores a freshly enhanced query through this same
contract and still reports ``analyze``: the "post-enhancement" label a reader
sees is applied by the client from context, not by a distinct record type.
"""

NO_OUTPUT_QUERY = ""
"""An analysis produces no rewritten query."""


def format_analyze(result: AnalyzeResult, runtime: RuntimeContext) -> dict[str, Any]:
    """Return one assessment in the analyze contract's shape."""
    if not isinstance(result, AnalyzeResult):
        raise OperationMismatchError(ANALYSIS_TYPE, type(result).__name__)
    return {
        "analysis": {
            "id": runtime.id,
            "ruleId": runtime.rule_id,
            "analysisType": ANALYSIS_TYPE,
            "inputQuery": runtime.input_query,
            "outputQuery": NO_OUTPUT_QUERY,
            "score": result.score,
            "rating": rating_from_score(result.score),
            "fpRisk": fp_risk(result.fp_risk),
            "feedback": result.summary,
            "strengths": list(result.strengths),
            "weaknesses": list(result.weaknesses),
            "findings": [
                {
                    "category": finding_category(finding.category),
                    "severity": finding.severity.value,
                    "title": finding.statement,
                    "detail": finding.explanation,
                }
                for finding in result.findings
            ],
            "suggestions": [
                {
                    "priority": priority(item.priority),
                    "title": item.action,
                    "description": item.rationale,
                    "codeSnippet": item.code_snippet,
                }
                for item in result.recommendations
            ],
            "evasionRisks": [
                {
                    "technique": risk.technique,
                    "description": risk.description,
                    "mitigation": risk.mitigation,
                }
                for risk in result.evasion_risks
            ],
            "mitreMappings": [attack_mapping(m) for m in result.mappings],
            "modelUsed": result.provenance.model,
            "tokensUsed": result.provenance.usage.total_tokens,
            "latencyMs": runtime.latency_ms,
            "userId": runtime.user_id,
            "createdAt": runtime.created_at,
        }
    }
