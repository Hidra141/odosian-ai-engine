"""Core engine layer.

Internal engine of the ODOSIAN AI Engine. Owns the engine, the pipeline, the
workflows and the operation dispatcher.

Analyze, enhance and generate are workflows rather than separate modules. They
share a single pipeline; the requested operation determines only which prompt
and which execution mode are used.

The pipeline is::

    ContextPackage -> prompt variables -> RenderedPrompt -> LLMRequest
                   -> LLMResponse -> strict JSON -> schema check
                   -> typed result -> reasoning validation

Everything before the context package is finished by the time this layer runs,
and everything about talking to a provider belongs to :mod:`src.llm`. This layer
adds the reasoning contract: what each operation must return, and what makes a
returned answer usable.

Typical use::

    engine = ReasoningEngine.create(provider, config)
    result = engine.analyze(AnalyzeRequest(package=context_package))

Two guarantees are worth knowing before depending on it. Uncertainty is
preserved: an identifier the context reported unresolved or ambiguous must come
back with that same status, and a response that settles one is rejected rather
than trusted. And malformed output is never repaired: a fenced, truncated or
otherwise broken body fails through Stage-07's strict parser with the fault
intact.
"""

from __future__ import annotations

from .context_view import FENCE_BEGIN, FENCE_END, FENCE_NOTICE, ContextView
from .engine import SHARED_PROMPT_REFS, ReasoningEngine
from .exceptions import (
    InvalidReasoningRequestError,
    PromptRenderingError,
    ReasoningError,
    ReasoningValidationError,
    ResponseSchemaError,
)
from .models import (
    AnalyzeRequest,
    AnalyzeResult,
    DetectionRuleDraft,
    EnhanceRequest,
    EnhanceResult,
    Evidence,
    Finding,
    GenerateRequest,
    GenerateResult,
    MappingClaim,
    MitreMapping,
    OperationResult,
    OriginalRule,
    RationaleEntry,
    ReasoningProvenance,
    ReasoningRequest,
    ReasoningResult,
    Recommendation,
    RuleChange,
    Uncertainty,
)
from .output_format import (
    ANALYZE_SPEC,
    ENHANCE_SPEC,
    GENERATE_SPEC,
    OPERATION_SPECS,
    json_schema_for,
    output_format_for,
    spec_for,
)
from .response_parser import ResponseParser, decode
from .schema import (
    FieldKind,
    FieldSpec,
    ObjectSpec,
    SchemaIssue,
    SchemaValidator,
    json_schema,
    render_object_spec,
)
from .types import (
    NO_MATERIAL,
    PROMPT_VARIABLES,
    ChangeCategory,
    EvidenceSource,
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
from .uncertainty import UncertainIdentifier, uncertain_identifiers
from .validation import (
    ReasoningIssue,
    ReasoningValidationResult,
    ReasoningValidator,
    SuppliedMaterial,
)

__all__ = [
    "ANALYZE_SPEC",
    "ENHANCE_SPEC",
    "FENCE_BEGIN",
    "FENCE_END",
    "FENCE_NOTICE",
    "GENERATE_SPEC",
    "NO_MATERIAL",
    "OPERATION_SPECS",
    "PROMPT_VARIABLES",
    "SHARED_PROMPT_REFS",
    "AnalyzeRequest",
    "AnalyzeResult",
    "ChangeCategory",
    "ContextView",
    "DetectionRuleDraft",
    "EnhanceRequest",
    "EnhanceResult",
    "Evidence",
    "EvidenceSource",
    "FieldKind",
    "FieldSpec",
    "Finding",
    "FindingCategory",
    "GenerateRequest",
    "GenerateResult",
    "ImportanceLevel",
    "InvalidReasoningRequestError",
    "MappingClaim",
    "MitreMapping",
    "ObjectSpec",
    "OperationResult",
    "OriginalRule",
    "OutputLanguage",
    "OutputRuleType",
    "OutputSeverity",
    "PromptRenderingError",
    "RationaleAspect",
    "RationaleEntry",
    "ReasoningEngine",
    "ReasoningError",
    "ReasoningIssue",
    "ReasoningOperation",
    "ReasoningProvenance",
    "ReasoningRequest",
    "ReasoningResult",
    "ReasoningValidationError",
    "ReasoningValidationResult",
    "ReasoningValidator",
    "Recommendation",
    "ResponseParser",
    "ResponseSchemaError",
    "RuleChange",
    "SchemaIssue",
    "SchemaValidator",
    "SupportLevel",
    "SuppliedMaterial",
    "UncertainIdentifier",
    "Uncertainty",
    "UncertaintyStatus",
    "decode",
    "json_schema",
    "json_schema_for",
    "output_format_for",
    "render_object_spec",
    "spec_for",
    "uncertain_identifiers",
]
