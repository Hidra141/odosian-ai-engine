"""Validation engine exceptions.

Raised when a caller asks for a result and will not accept an invalid one.

The hierarchy mirrors the categories rather than the checks: a caller that wants
to treat a fabricated citation differently from a malformed field can catch
:class:`EvidenceValidationError` without enumerating individual codes, and one
that treats every failure alike catches :class:`ValidationEngineError`.

Every exception carries the whole report, not a summarised message, so nothing
found is lost by raising. The type is chosen from the most serious category
present, in the fixed order the report itself uses, so the same report always
raises the same type.

These are distinct from the LLM layer's exceptions on purpose. A response that
was never valid JSON is Stage-07's problem and raises there; a response that
parsed cleanly and then said something it may not say is this layer's, and
conflating the two would make a provider fault indistinguishable from a
reasoning fault.
"""

from __future__ import annotations

from .models import ValidationReport
from .types import CategoryOrder, ValidationCategory


class ValidationEngineError(Exception):
    """Base class for every validation engine failure."""

    category: ValidationCategory | None = None

    def __init__(self, report: ValidationReport) -> None:
        """Record the report that caused the refusal."""
        super().__init__(
            f"Validation failed for operation {report.operation.value!r}: "
            + "; ".join(str(issue) for issue in report.errors)
        )
        self.report = report

    @property
    def issues(self) -> tuple[str, ...]:
        """Return every blocking issue rendered as a line."""
        return tuple(str(issue) for issue in self.report.errors)


class StructuralValidationError(ValidationEngineError):
    """The result's own shape is wrong: a field, a type, a range, a reference."""

    category = ValidationCategory.STRUCTURAL


class EvidenceValidationError(ValidationEngineError):
    """The result cites material the context package did not supply."""

    category = ValidationCategory.EVIDENCE


class UncertaintyValidationError(ValidationEngineError):
    """An identifier the context left unsettled did not survive unchanged."""

    category = ValidationCategory.UNCERTAINTY


class RuleIntegrityValidationError(ValidationEngineError):
    """A produced or preserved detection rule is unusable or misrepresented."""

    category = ValidationCategory.RULE_INTEGRITY


class SecurityValidationError(ValidationEngineError):
    """The result carries something that must never leave the engine."""

    category = ValidationCategory.SECURITY


class ProvenanceValidationError(ValidationEngineError):
    """A citation no longer traces back to the material it names."""

    category = ValidationCategory.PROVENANCE


_BY_CATEGORY: dict[ValidationCategory, type[ValidationEngineError]] = {
    ValidationCategory.STRUCTURAL: StructuralValidationError,
    ValidationCategory.EVIDENCE: EvidenceValidationError,
    ValidationCategory.UNCERTAINTY: UncertaintyValidationError,
    ValidationCategory.RULE_INTEGRITY: RuleIntegrityValidationError,
    ValidationCategory.SECURITY: SecurityValidationError,
    ValidationCategory.PROVENANCE: ProvenanceValidationError,
}


def error_for(report: ValidationReport) -> ValidationEngineError:
    """Return the exception a failing report should raise.

    The category of the first blocking issue in report order decides, which is
    the lowest :class:`~src.validation.types.CategoryOrder` present. Structural
    faults therefore win over evidence faults, because a result whose shape is
    wrong cannot be meaningfully judged on what it cites.
    """
    blocking = report.errors
    if not blocking:
        raise ValueError("a valid report has no exception to raise")
    category = min((issue.category for issue in blocking), key=CategoryOrder.of)
    return _BY_CATEGORY[category](report)
