"""Validation engine.

Validation of AI output before it is returned to the caller.

The post-reasoning safety boundary. A reasoning result and the context package
that produced it go in; a deterministic report comes out, and with it the
decision to accept the result or refuse it.

    Stage-15 result + ContextPackage -> ValidationEngine -> ValidationReport
                                                         -> accepted, or a typed refusal

Six categories are checked: the result's own **structure**, the **evidence** it
cites, the **uncertainty** it was obliged to carry forward, the **integrity** of
any rule it produced, what it carries out of the engine (**security**), and
whether its citations still trace home (**provenance**).

Some of these repeat a check Stage-15 already made, on purpose. Stage-15
validates the response it has just parsed; this validates whatever reaches the
boundary — a result restored from a cache, assembled by an application, replayed
from a log — so the guarantees do not depend on how the result arrived. Where
the two agree, they agree independently: this layer re-reads the package and the
result rather than trusting an earlier verdict.

Nothing here repairs. An invalid result is reported and refused, never quietly
corrected, because a result that has been silently adjusted is one nobody
reviewed.

Typical use::

    report = ValidationEngine().validate(result, package)
    if not report.is_valid:
        for issue in report.errors:
            log.warning("%s", issue)

    # or, when an invalid result must not proceed at all:
    accepted = ValidationEngine().validate_or_raise(result, package)

This layer opens no file, reads no dataset, holds no credential and makes no
network call.
"""

from __future__ import annotations

from .checks import (
    EvidenceChecker,
    ProvenanceChecker,
    RuleIntegrityChecker,
    SecurityChecker,
    StructuralChecker,
    UncertaintyChecker,
)
from .engine import ValidationEngine, issue_codes, validate
from .exceptions import (
    EvidenceValidationError,
    ProvenanceValidationError,
    RuleIntegrityValidationError,
    SecurityValidationError,
    StructuralValidationError,
    UncertaintyValidationError,
    ValidationEngineError,
    error_for,
)
from .models import ValidationIssue, ValidationReport
from .supplied import SuppliedContext, citations, texts
from .types import (
    CategoryOrder,
    IssueSeverity,
    ValidationCategory,
    ValidationCode,
)

__all__ = [
    "CategoryOrder",
    "EvidenceChecker",
    "EvidenceValidationError",
    "IssueSeverity",
    "ProvenanceChecker",
    "ProvenanceValidationError",
    "RuleIntegrityChecker",
    "RuleIntegrityValidationError",
    "SecurityChecker",
    "SecurityValidationError",
    "StructuralChecker",
    "StructuralValidationError",
    "SuppliedContext",
    "UncertaintyChecker",
    "UncertaintyValidationError",
    "ValidationCategory",
    "ValidationCode",
    "ValidationEngine",
    "ValidationEngineError",
    "ValidationIssue",
    "ValidationReport",
    "citations",
    "error_for",
    "issue_codes",
    "texts",
    "validate",
]
