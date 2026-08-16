"""The formatter.

One entry point over three operation-specific paths.

Dispatch is by result type, not by a flag the caller passes, so an enhance
result cannot be rendered as an analysis by mistake. Each path builds its own
contract and shares nothing but the small deterministic conversions in
:mod:`~src.formatter.normalize` — there is no universal response object, because
the three documents are not variations of one shape.

This layer validates nothing. Stage-16 decided whether the result may be
returned; if it said no, the result should not have reached here.
"""

from __future__ import annotations

from typing import Any

from src.core.models import AnalyzeResult, EnhanceResult, GenerateResult, OperationResult

from .analyze import format_analyze
from .enhance import format_enhance
from .exceptions import OperationMismatchError
from .generate import format_generate
from .runtime import RuntimeContext


def format_result(result: OperationResult, runtime: RuntimeContext) -> dict[str, Any]:
    """Return one validated result in the contract of the operation that produced it."""
    match result:
        case AnalyzeResult():
            return format_analyze(result, runtime)
        case EnhanceResult():
            return format_enhance(result, runtime)
        case GenerateResult():
            return format_generate(result, runtime)
        case _:
            raise OperationMismatchError("a reasoning result", type(result).__name__)
