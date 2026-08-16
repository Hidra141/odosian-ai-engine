"""The generate contract.

A newly written rule rendered as ``05-generate.jsonc`` states it.

``score`` here is the model's own assessment of the rule it just wrote, and is
not the same quantity as ``riskScore`` beside it: one grades the detection, the
other states how severe a hit is. They are never derived from each other.

There is no ``rating``. The contract does not carry one for a generation, so
none is computed.

``savedRuleId`` and ``savedRuleTitle`` sit outside ``analysis`` and appear only
when the request asked for the rule to be saved. They are omitted rather than
sent as null, which is what the contract demonstrates.
"""

from __future__ import annotations

from typing import Any, Final

from src.core.models import GenerateResult

from .exceptions import OperationMismatchError
from .normalize import attack_mapping, language
from .runtime import RuntimeContext

ANALYSIS_TYPE = "generate"

DEFAULT_INTERVAL: Final[str] = "5m"
DEFAULT_FROM_TIME: Final[str] = "now-6m"
DEFAULT_MAX_SIGNALS: Final[int] = 100
"""The schedule the contract defaults to.

Taken from ``17-validation-schemas.jsonc``, which states each default outright.
The engine does not produce them and is not asked to: a schedule is an
operational setting, not something to reason about from a corpus.
"""

NO_REFERENCES: tuple[str, ...] = ()
"""The engine states no external references, and the contract defaults to none."""


def format_generate(result: GenerateResult, runtime: RuntimeContext) -> dict[str, Any]:
    """Return one generated rule in the generate contract's shape."""
    if not isinstance(result, GenerateResult):
        raise OperationMismatchError(ANALYSIS_TYPE, type(result).__name__)
    rule = result.generated_rule
    document: dict[str, Any] = {
        "analysis": {
            "id": runtime.id,
            "analysisType": ANALYSIS_TYPE,
            "modelUsed": result.provenance.model,
            "tokensUsed": result.provenance.usage.total_tokens,
            "latencyMs": runtime.latency_ms,
            "userId": runtime.user_id,
            "createdAt": runtime.created_at,
            "title": rule.title,
            "description": rule.description,
            "query": rule.query,
            "language": language(rule.language),
            "ruleType": rule.rule_type.value,
            "severity": rule.severity.value,
            "riskScore": rule.risk_score,
            "tags": list(rule.tags),
            "indexPatterns": list(rule.index_patterns),
            "interval": DEFAULT_INTERVAL,
            "fromTime": DEFAULT_FROM_TIME,
            "maxSignals": DEFAULT_MAX_SIGNALS,
            "investigationGuide": rule.investigation_guide,
            "falsePositives": list(rule.false_positives),
            "references": list(NO_REFERENCES),
            "mitreMappings": [attack_mapping(m) for m in result.mappings],
            "score": result.score,
            "notes": result.notes,
        }
    }
    if runtime.saved:
        document["savedRuleId"] = runtime.saved_rule_id
        document["savedRuleTitle"] = runtime.saved_rule_title
    return document
