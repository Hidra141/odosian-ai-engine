"""Validation vocabulary.

The categories a validation issue falls into, how much an issue matters, and the
stable code that names it.

Codes are the contract. A caller may branch on ``ValidationCode.UNCERTAINTY_
STATUS_PROMOTED`` and keep working when the message wording changes, so the
codes are treated as public API: renaming one is a breaking change, and the
``category.name`` spelling keeps them readable in a log line without a lookup
table.

Nothing here judges a rule's quality. Severity says whether an issue blocks
acceptance, not whether a detection is good.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class ValidationCategory(StrEnum):
    """The kind of property an issue is about."""

    STRUCTURAL = "structural"
    """The result's own shape: fields, types, ranges, internal references."""

    EVIDENCE = "evidence"
    """What the result cites, and whether the context package supplied it."""

    UNCERTAINTY = "uncertainty"
    """Whether unsettled identifiers survived reasoning unchanged."""

    RULE_INTEGRITY = "rule_integrity"
    """Whether a produced or preserved detection rule is usable and honest."""

    SECURITY = "security"
    """What must never leave the engine inside a result."""

    PROVENANCE = "provenance"
    """Whether a citation still traces back to the material it names."""


class IssueSeverity(StrEnum):
    """Whether an issue blocks acceptance."""

    ERROR = "error"
    """The result must not be accepted."""

    WARNING = "warning"
    """The result is usable, but a reviewer should see this."""


class CategoryOrder(IntEnum):
    """The order categories are reported in.

    Fixed so that two runs over the same result produce the same report, and so
    that the checks a reader most needs first — what is wrong with the shape,
    then what is unsupported — come before the advisory ones.
    """

    STRUCTURAL = 0
    EVIDENCE = 1
    UNCERTAINTY = 2
    RULE_INTEGRITY = 3
    SECURITY = 4
    PROVENANCE = 5

    @classmethod
    def of(cls, category: ValidationCategory) -> int:
        """Return the sort position of a category."""
        return int(cls[category.name])


class ValidationCode(StrEnum):
    """The stable identifier of one kind of validation issue."""

    # Structural
    OPERATION_MISMATCH = "structural.operation_mismatch"
    RESULT_TYPE_MISMATCH = "structural.result_type_mismatch"
    MISSING_VALUE = "structural.missing_value"
    INVALID_ENUM = "structural.invalid_enum"
    OUT_OF_RANGE = "structural.out_of_range"
    MULTILINE_STRING = "structural.multiline_string"
    DUPLICATE_ID = "structural.duplicate_id"
    UNKNOWN_REFERENCE = "structural.unknown_reference"
    UNDECLARED_FIELD = "structural.undeclared_field"
    IMPOSSIBLE_COMBINATION = "structural.impossible_combination"

    # Evidence
    UNKNOWN_ITEM = "evidence.unknown_item"
    FABRICATED_IDENTIFIER = "evidence.fabricated_identifier"
    UNSUPPORTED_CLAIM = "evidence.unsupported_claim"
    EMPTY_CITATION = "evidence.empty_citation"

    # Uncertainty
    UNCERTAINTY_DROPPED = "uncertainty.dropped"
    UNCERTAINTY_STATUS_PROMOTED = "uncertainty.status_promoted"
    AMBIGUITY_NARROWED = "uncertainty.ambiguity_narrowed"
    FABRICATED_CANDIDATE = "uncertainty.fabricated_candidate"
    FABRICATED_UNCERTAINTY = "uncertainty.fabricated_uncertainty"
    UNCERTAINTY_PRESENTED_AS_FACT = "uncertainty.presented_as_fact"
    UNSETTLED_IDENTIFIER_IN_RULE = "uncertainty.unsettled_identifier_in_rule"

    # Rule integrity
    ORIGINAL_RULE_ALTERED = "rule_integrity.original_altered"
    RULE_UNCHANGED = "rule_integrity.unchanged"
    NO_CHANGES_ACCOUNTED = "rule_integrity.no_changes_accounted"
    NO_RATIONALE = "rule_integrity.no_rationale"
    INCOMPLETE_RULE = "rule_integrity.incomplete_rule"
    LANGUAGE_TYPE_MISMATCH = "rule_integrity.language_type_mismatch"
    RISK_SEVERITY_MISMATCH = "rule_integrity.risk_severity_mismatch"
    FABRICATED_MAPPING = "rule_integrity.fabricated_mapping"

    # Security
    CREDENTIAL_IN_RESULT = "security.credential_in_result"
    TEMPLATE_ARTIFACT = "security.template_artifact"
    FENCE_ARTIFACT = "security.fence_artifact"
    FABRICATED_REFERENCE = "security.fabricated_reference"

    # Provenance
    CITATION_SOURCE_MISMATCH = "provenance.source_mismatch"
    CITATION_NOT_TRACEABLE = "provenance.not_traceable"
    EVIDENCE_STATUS_NOT_PRESERVED = "provenance.status_not_preserved"

    @property
    def category(self) -> ValidationCategory:
        """Return the category this code belongs to, read from the code itself."""
        return ValidationCategory(self.value.split(".", 1)[0])
