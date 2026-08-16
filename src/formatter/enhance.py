"""The enhance contract.

A rewrite rendered as ``03-enhance.jsonc`` states it.

``score`` and ``rating`` are fixed at ``0`` and ``""``. They are not a grade of
zero: an enhancement rewrites a rule rather than scoring one, and the contract
records that with sentinels the interface reads as "not applicable". Passing an
analysis rating through here would assert a quality judgement nobody made.

The mappings are ``newMitreMappings`` and stay distinct from an analysis's
``mitreMappings``. The contract keeps them apart because they mean different
things: these are proposed, and become real only once a later analysis confirms
them.
"""

from __future__ import annotations

from typing import Any

from src.core.models import EnhanceResult

from .exceptions import OperationMismatchError
from .normalize import attack_mapping, change_label
from .runtime import RuntimeContext

ANALYSIS_TYPE = "enhance"

NOT_SCORED = 0
"""An enhancement carries no detection-quality score."""

NOT_RATED = ""
"""An enhancement carries no letter grade."""

NO_REFERENCES: tuple[str, ...] = ()
"""The engine states no external references, and the contract defaults to none."""


def format_enhance(result: EnhanceResult, runtime: RuntimeContext) -> dict[str, Any]:
    """Return one rewrite in the enhance contract's shape."""
    if not isinstance(result, EnhanceResult):
        raise OperationMismatchError(ANALYSIS_TYPE, type(result).__name__)
    rule = result.enhanced_rule
    return {
        "analysis": {
            "id": runtime.id,
            "ruleId": runtime.rule_id,
            "analysisType": ANALYSIS_TYPE,
            "inputQuery": result.original_rule.query,
            "score": NOT_SCORED,
            "rating": NOT_RATED,
            "modelUsed": result.provenance.model,
            "tokensUsed": result.provenance.usage.total_tokens,
            "latencyMs": runtime.latency_ms,
            "userId": runtime.user_id,
            "createdAt": runtime.created_at,
            "enhancedQuery": rule.query,
            "changelog": [
                {"change": change_label(change), "reason": change.rationale}
                for change in result.changes
            ],
            "newSeverity": rule.severity.value,
            "newRiskScore": rule.risk_score,
            "investigationGuide": rule.investigation_guide,
            "falsePositives": list(rule.false_positives),
            "references": list(NO_REFERENCES),
            "indexPatterns": list(rule.index_patterns),
            "newMitreMappings": [attack_mapping(m) for m in rule.mitre],
            "enhancedTitle": rule.title,
            "enhancedDescription": rule.description,
        }
    }
