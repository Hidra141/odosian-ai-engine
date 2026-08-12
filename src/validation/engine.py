"""Validation engine.

The boundary a reasoning result crosses before an application may act on it.

    ReasoningResult + ContextPackage
        -> six category checks
        -> ValidationReport (deterministically ordered)
        -> accepted, or a typed refusal

The engine runs every check and collects everything, rather than stopping at the
first fault: a caller fixing a prompt wants the whole list, not one item at a
time. It never repairs a result, never fills a missing value, never drops an
issue it cannot explain, and never mutates either input.

It is also the layer that can say no to a result nothing else examined. Stage-15
validates the response it parsed; this validates whatever arrives — a result
restored from a cache, assembled by an application, or replayed from a log — so
the guarantees hold regardless of how a result was produced.

This layer opens no file, reads no dataset, holds no credential and makes no
network call. Everything it needs is in the two objects it is handed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import final

from src.context.models import ContextPackage
from src.core.models import OperationResult
from src.core.types import ReasoningOperation

from .checks import (
    EvidenceChecker,
    ProvenanceChecker,
    RuleIntegrityChecker,
    SecurityChecker,
    StructuralChecker,
    UncertaintyChecker,
)
from .exceptions import error_for
from .models import ValidationIssue, ValidationReport
from .supplied import SuppliedContext


@final
@dataclass(frozen=True, slots=True)
class ValidationEngine:
    """Validates a reasoning result against the context that produced it."""

    structural: StructuralChecker = field(default_factory=StructuralChecker)
    evidence: EvidenceChecker = field(default_factory=EvidenceChecker)
    uncertainty: UncertaintyChecker = field(default_factory=UncertaintyChecker)
    rule_integrity: RuleIntegrityChecker = field(default_factory=RuleIntegrityChecker)
    security: SecurityChecker = field(default_factory=SecurityChecker)
    provenance: ProvenanceChecker = field(default_factory=ProvenanceChecker)

    def validate(
        self,
        result: OperationResult,
        package: ContextPackage,
        *,
        operation: ReasoningOperation | None = None,
        rule_text: str = "",
    ) -> ValidationReport:
        """Return the report of validating one result.

        ``operation`` defaults to the operation the package was built for, so a
        caller cannot accidentally validate an enhance result against an analyze
        package by omitting it. ``rule_text`` admits a rule supplied straight to
        the engine, which the package's own items would not carry.
        """
        expected = (
            operation
            if operation is not None
            else ReasoningOperation.from_context(package.operation)
        )
        supplied = SuppliedContext.of(package, rule_text)
        issues: list[ValidationIssue] = []
        for checker in (
            self.structural,
            self.evidence,
            self.uncertainty,
            self.rule_integrity,
            self.security,
            self.provenance,
        ):
            issues.extend(checker.check(result, supplied, expected))
        return ValidationReport.of(expected, issues)

    def validate_or_raise(
        self,
        result: OperationResult,
        package: ContextPackage,
        *,
        operation: ReasoningOperation | None = None,
        rule_text: str = "",
    ) -> OperationResult:
        """Return the result when it validates, or raise a typed refusal.

        The result is returned unchanged — the same object, not a copy — because
        this layer's answer is yes or no, never "here is a fixed one".
        """
        report = self.validate(result, package, operation=operation, rule_text=rule_text)
        if not report.is_valid:
            raise error_for(report)
        return result

    def accepts(self, result: OperationResult, package: ContextPackage) -> bool:
        """Return whether a result would be accepted, without raising."""
        return self.validate(result, package).is_valid


def validate(
    result: OperationResult,
    package: ContextPackage,
    *,
    operation: ReasoningOperation | None = None,
    rule_text: str = "",
) -> ValidationReport:
    """Validate one result with a default engine."""
    return ValidationEngine().validate(
        result, package, operation=operation, rule_text=rule_text
    )


def issue_codes(issues: Sequence[ValidationIssue]) -> tuple[str, ...]:
    """Return the codes of a sequence of issues, for compact reporting."""
    return tuple(issue.code.value for issue in issues)
