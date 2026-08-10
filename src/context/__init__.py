"""Context builder.

Assembly of the final context supplied to the language model.

The layer takes what the earlier stages produced — a parsed rule, its extracted
and mapped entities, and a Stage-13 ``RetrievalResult`` — and arranges them into
one auditable :class:`ContextPackage`. It selects and organises evidence. It
does not retrieve, rank, resolve, render or reason.

Every item traces home: context item → retrieval chunk → parent record → source
dataset, with the graph path preserved wherever traversal justified the item. An
identifier the retrieval layer could not resolve arrives here as an item that
says so, and an ambiguous one arrives with every candidate intact. Neither is
ever quietly promoted into a fact.

Construction is deterministic. There are no timestamps, no random identifiers
and no content-dependent ordering, so identical inputs produce an identical
package. Reduction to fit a budget is never silent: each cut marks its item,
marks its section and raises a warning.

This layer opens no file, touches no dataset and imports no provider SDK.

Typical use::

    package = ContextBuilder().build(
        ContextOperation.ANALYZE,
        rule=parsed_rule,
        entities=extracted,
        mappings=mapped,
        retrieval=result,
    )
    ContextValidator().validate(package).raise_if_invalid()
"""

from __future__ import annotations

from .budget import TRUNCATION_MARKER, BudgetEnforcer, BudgetOutcome
from .context_builder import ContextBuilder, rule_context_from_parsed
from .evidence import EvidenceBatch, EvidenceExtractor, redact
from .exceptions import (
    ContextBudgetExceededError,
    ContextBuildError,
    ContextError,
    ContextValidationError,
    SecretLeakError,
)
from .models import (
    ContextBudget,
    ContextItem,
    ContextPackage,
    ContextSection,
    ContextWarning,
    GraphTrace,
    ItemProvenance,
    PackageProvenance,
    RuleContext,
)
from .organizer import EvidenceOrganizer, sort_key
from .types import (
    SECTION_ORDER,
    ContextOperation,
    EvidenceKind,
    EvidencePriority,
    EvidenceStatus,
    SectionName,
    TruncationPolicy,
    WarningCode,
)
from .validation import ContextIssue, ContextValidationResult, ContextValidator

__all__ = [
    "SECTION_ORDER",
    "TRUNCATION_MARKER",
    "BudgetEnforcer",
    "BudgetOutcome",
    "ContextBudget",
    "ContextBudgetExceededError",
    "ContextBuildError",
    "ContextBuilder",
    "ContextError",
    "ContextIssue",
    "ContextItem",
    "ContextOperation",
    "ContextPackage",
    "ContextSection",
    "ContextValidationError",
    "ContextValidationResult",
    "ContextValidator",
    "ContextWarning",
    "EvidenceBatch",
    "EvidenceExtractor",
    "EvidenceKind",
    "EvidenceOrganizer",
    "EvidencePriority",
    "EvidenceStatus",
    "GraphTrace",
    "ItemProvenance",
    "PackageProvenance",
    "RuleContext",
    "SectionName",
    "TruncationPolicy",
    "WarningCode",
    "redact",
    "rule_context_from_parsed",
    "sort_key",
]
