"""Formatter.

Conversion of validated results into the official JSON output schema.

The last layer. A result that passed the Stage-16 boundary goes in with the
application's own record of the request, and the operation's contract document
comes out.

    accepted result + RuntimeContext -> format_result -> operation contract

Three contracts, not one. An assessment, a rewrite and a newly written rule are
different documents — an analysis carries a grade and no rule, a rewrite carries
sentinels where a grade would be, a generation carries a schedule and no rule id
— so each has its own path and they share only the small deterministic
conversions between the engine's vocabulary and the API's.

Nothing here reasons, retrieves, validates or invents. Where the contract needs
something the engine cannot know — who asked, when, how long it took — the
caller supplies it in a :class:`RuntimeContext`, and a caller that omits one
fails at construction rather than shipping a plausible blank.

Typical use::

    accepted = ValidationEngine().validate_or_raise(result, package)
    document = format_result(accepted, runtime)
"""

from __future__ import annotations

from .analyze import format_analyze
from .enhance import format_enhance
from .exceptions import (
    FormatterError,
    OperationMismatchError,
    ScoreOutOfRangeError,
)
from .formatter import format_result
from .generate import format_generate
from .normalize import (
    attack_mapping,
    change_label,
    confidence,
    finding_category,
    fp_risk,
    language,
    priority,
)
from .rating import BANDS, rating_from_score
from .runtime import RuntimeContext

__all__ = [
    "BANDS",
    "FormatterError",
    "OperationMismatchError",
    "RuntimeContext",
    "ScoreOutOfRangeError",
    "attack_mapping",
    "change_label",
    "confidence",
    "finding_category",
    "format_analyze",
    "format_enhance",
    "format_generate",
    "format_result",
    "fp_risk",
    "language",
    "priority",
    "rating_from_score",
]
