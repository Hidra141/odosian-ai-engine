"""Output format.

The concrete JSON contract of each reasoning operation: the value of the
``{{OUTPUT_FORMAT}}`` placeholder that ``prompts/shared/output.md`` leaves for
this layer to supply.

Every operation extends the shared envelope — ``operation``, ``summary``,
``findings``, ``recommendations``, ``confidence``, ``metadata`` — rather than
replacing it, so a consumer can read the common part of any result without
knowing which operation produced it. The envelope is restated here field by
field because this module, not the template, is what the validator enforces.

Three decisions shape the schemas:

* **Citations are checkable.** Every claim carries evidence naming a context
  item by the id the package assigned it. A citation of an item that was never
  supplied is detectable, which is what makes "do not fabricate references" an
  enforced rule rather than an instruction.
* **Uncertainty is a field, not a footnote.** Every operation carries
  ``uncertainties``, and an identifier the context reports unresolved or
  ambiguous must appear there with that same status. There is no ``resolved``
  member for it to be promoted to.
* **Nothing optional.** Every declared field is required, with an empty array or
  an empty object standing for "no value". A field that may vanish is a field
  whose absence cannot be distinguished from an omission.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from src.llm.types import JSONValue

from .schema import (
    FieldKind,
    FieldSpec,
    ObjectSpec,
    json_schema,
    render_object_spec,
)
from .types import (
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
)


def _values(members: type[StrEnum]) -> tuple[str, ...]:
    """Return an enumeration's values in declaration order."""
    return tuple(member.value for member in members)


EVIDENCE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="Evidence",
    description="A pointer to the supplied material a claim rests on.",
    fields=(
        FieldSpec(
            name="item_id",
            kind=FieldKind.STRING,
            description=(
                "The id of the context item supporting the claim, copied exactly from the "
                "supplied material, for example 'retrieval:0003'."
            ),
        ),
        FieldSpec(
            name="source",
            kind=FieldKind.STRING,
            description="Which supplied material the item came from.",
            enum=_values(EvidenceSource),
        ),
        FieldSpec(
            name="identifier",
            kind=FieldKind.STRING,
            description=(
                "The identifier the item establishes, reproduced exactly as supplied, for "
                "example 'T1059.001' or 'process.command_line'. Empty string when the item "
                "carries none."
            ),
            allow_empty=True,
        ),
        FieldSpec(
            name="detail",
            kind=FieldKind.STRING,
            description="What this item establishes, in one line.",
        ),
    ),
)

UNCERTAINTY_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="Uncertainty",
    description="An identifier the supplied context could not settle.",
    fields=(
        FieldSpec(
            name="identifier",
            kind=FieldKind.STRING,
            description="The identifier, exactly as the context reports it.",
        ),
        FieldSpec(
            name="status",
            kind=FieldKind.STRING,
            description=(
                "The state the context reports. Copy it; never upgrade an unresolved or "
                "ambiguous identifier to a settled one."
            ),
            enum=("unresolved", "ambiguous"),
        ),
        FieldSpec(
            name="candidates",
            kind=FieldKind.STRING_ARRAY,
            description=(
                "Every candidate the context lists for an ambiguous identifier, all of them, "
                "in the order supplied. Empty array for an unresolved identifier."
            ),
        ),
        FieldSpec(
            name="treatment",
            kind=FieldKind.STRING,
            description=(
                "How this uncertainty was handled in your answer, in one line. Say what you "
                "did not conclude because of it."
            ),
        ),
    ),
)

FINDING_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="Finding",
    description="An observation about the rule as it currently stands.",
    fields=(
        FieldSpec(
            name="finding_id",
            kind=FieldKind.STRING,
            description="A short identifier unique within this response, for example 'F1'.",
        ),
        FieldSpec(
            name="category",
            kind=FieldKind.STRING,
            description="The dimension this finding speaks about.",
            enum=_values(FindingCategory),
        ),
        FieldSpec(
            name="severity",
            kind=FieldKind.STRING,
            description="How much this finding matters for the rule's behaviour in production.",
            enum=_values(ImportanceLevel),
        ),
        FieldSpec(
            name="statement",
            kind=FieldKind.STRING,
            description="The claim about the rule, in one line.",
        ),
        FieldSpec(
            name="explanation",
            kind=FieldKind.STRING,
            description="Why the supplied material leads to that claim.",
        ),
        FieldSpec(
            name="support",
            kind=FieldKind.STRING,
            description=(
                "How well the supplied context supports the claim. 'unsupported' is a valid "
                "and useful answer where the context is silent."
            ),
            enum=_values(SupportLevel),
        ),
        FieldSpec(
            name="evidence",
            kind=FieldKind.OBJECT_ARRAY,
            description=(
                "The supplied items the claim rests on. Empty array only where the finding "
                "reports the absence of material."
            ),
            spec=EVIDENCE_SPEC,
        ),
        FieldSpec(
            name="confidence",
            kind=FieldKind.NUMBER,
            description="How well the context supported this finding, from 0.0 to 1.0.",
            minimum=0.0,
            maximum=1.0,
        ),
    ),
)

RECOMMENDATION_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="Recommendation",
    description="A proposed change to the rule.",
    fields=(
        FieldSpec(
            name="recommendation_id",
            kind=FieldKind.STRING,
            description="A short identifier unique within this response, for example 'R1'.",
        ),
        FieldSpec(
            name="category",
            kind=FieldKind.STRING,
            description="The dimension this recommendation addresses.",
            enum=_values(FindingCategory),
        ),
        FieldSpec(
            name="priority",
            kind=FieldKind.STRING,
            description="How urgently the change should be made.",
            enum=_values(ImportanceLevel),
        ),
        FieldSpec(
            name="action",
            kind=FieldKind.STRING,
            description="The change to make, stated concretely enough to act on.",
        ),
        FieldSpec(
            name="rationale",
            kind=FieldKind.STRING,
            description="What the change achieves, and why the supplied material justifies it.",
        ),
        FieldSpec(
            name="addresses",
            kind=FieldKind.STRING_ARRAY,
            description=(
                "The finding_id values this recommendation answers. Every value must name a "
                "finding in this same response. Empty array where it answers none."
            ),
        ),
        FieldSpec(
            name="support",
            kind=FieldKind.STRING,
            description="How well the supplied context supports the change.",
            enum=_values(SupportLevel),
        ),
    ),
)

MITRE_MAPPING_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="MitreMapping",
    description="One ATT&CK mapping a rule declares.",
    fields=(
        FieldSpec(
            name="tactic_id",
            kind=FieldKind.STRING,
            description=(
                "The tactic identifier in official form, for example 'TA0002'. Use only "
                "identifiers present in the supplied MITRE material. Empty string where the "
                "supplied material establishes none."
            ),
            allow_empty=True,
        ),
        FieldSpec(
            name="technique_id",
            kind=FieldKind.STRING,
            description=(
                "The technique identifier in official form, for example 'T1059.001'. Use only "
                "identifiers present in the supplied MITRE material."
            ),
        ),
    ),
)

RULE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="Rule",
    description="A complete detection rule.",
    fields=(
        FieldSpec(
            name="title",
            kind=FieldKind.STRING,
            description="The rule's name, describing the behaviour it detects.",
        ),
        FieldSpec(
            name="description",
            kind=FieldKind.STRING,
            description="What the rule detects and why it matters, in one line.",
        ),
        FieldSpec(
            name="rule_type",
            kind=FieldKind.STRING,
            description="The Elastic rule type.",
            enum=_values(OutputRuleType),
        ),
        FieldSpec(
            name="language",
            kind=FieldKind.STRING,
            description="The query language the query is written in.",
            enum=_values(OutputLanguage),
        ),
        FieldSpec(
            name="query",
            kind=FieldKind.STRING,
            description=(
                "The complete query, on a single line. Reference only fields the supplied "
                "material confirms exist."
            ),
        ),
        FieldSpec(
            name="severity",
            kind=FieldKind.STRING,
            description=(
                "The consequence of the detected behaviour, not the detection's confidence."
            ),
            enum=_values(OutputSeverity),
        ),
        FieldSpec(
            name="risk_score",
            kind=FieldKind.INTEGER,
            description="The risk score accompanying the severity, from 0 to 100.",
            minimum=0,
            maximum=100,
        ),
        FieldSpec(
            name="index_patterns",
            kind=FieldKind.STRING_ARRAY,
            description=(
                "The indices the rule runs against. Empty array where the supplied material "
                "establishes none."
            ),
        ),
        FieldSpec(
            name="false_positives",
            kind=FieldKind.STRING_ARRAY,
            description="The benign activity a deployment should expect this rule to match.",
        ),
        FieldSpec(
            name="investigation_guide",
            kind=FieldKind.STRING,
            description="The triage steps an analyst follows when the rule fires, in one line.",
        ),
        FieldSpec(
            name="mitre",
            kind=FieldKind.OBJECT_ARRAY,
            description=(
                "The rule's ATT&CK mapping. Empty array where the supplied material supports "
                "none."
            ),
            spec=MITRE_MAPPING_SPEC,
        ),
    ),
)

ORIGINAL_RULE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="OriginalRule",
    description="The rule as it was supplied, identified rather than reproduced in full.",
    fields=(
        FieldSpec(
            name="identifier",
            kind=FieldKind.STRING,
            description=(
                "The supplied rule's identifier, copied exactly. Empty string where the "
                "supplied rule carries none."
            ),
            allow_empty=True,
        ),
        FieldSpec(
            name="title",
            kind=FieldKind.STRING,
            description="The supplied rule's title, copied exactly.",
        ),
        FieldSpec(
            name="language",
            kind=FieldKind.STRING,
            description=(
                "The query language of the supplied rule, as supplied. Empty string where the "
                "supplied rule does not state one."
            ),
            allow_empty=True,
        ),
        FieldSpec(
            name="query",
            kind=FieldKind.STRING,
            description="The supplied rule's query, copied exactly, on a single line.",
        ),
    ),
)

CHANGE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="Change",
    description="One change made to the original rule, with its justification.",
    fields=(
        FieldSpec(
            name="change_id",
            kind=FieldKind.STRING,
            description="A short identifier unique within this response, for example 'C1'.",
        ),
        FieldSpec(
            name="category",
            kind=FieldKind.STRING,
            description="What the change was made for.",
            enum=_values(ChangeCategory),
        ),
        FieldSpec(
            name="before",
            kind=FieldKind.STRING,
            description=(
                "The original condition, field or value, on a single line. Empty string where "
                "the change adds something the original did not have."
            ),
            allow_empty=True,
        ),
        FieldSpec(
            name="after",
            kind=FieldKind.STRING,
            description=(
                "The replacement, on a single line. Empty string where the change removes "
                "something."
            ),
            allow_empty=True,
        ),
        FieldSpec(
            name="rationale",
            kind=FieldKind.STRING,
            description="The problem in the original rule this change answers.",
        ),
        FieldSpec(
            name="addresses",
            kind=FieldKind.STRING_ARRAY,
            description=(
                "The finding_id values this change answers. Every value must name a finding "
                "in this same response."
            ),
        ),
        FieldSpec(
            name="evidence",
            kind=FieldKind.OBJECT_ARRAY,
            description="The supplied items justifying the change.",
            spec=EVIDENCE_SPEC,
        ),
        FieldSpec(
            name="support",
            kind=FieldKind.STRING,
            description="How well the supplied context supports the change.",
            enum=_values(SupportLevel),
        ),
    ),
)

RATIONALE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="Rationale",
    description="One authoring decision behind the generated rule.",
    fields=(
        FieldSpec(
            name="aspect",
            kind=FieldKind.STRING,
            description="The decision being accounted for.",
            enum=_values(RationaleAspect),
        ),
        FieldSpec(
            name="statement",
            kind=FieldKind.STRING,
            description="The decision taken, in one line.",
        ),
        FieldSpec(
            name="rationale",
            kind=FieldKind.STRING,
            description="Why the supplied material leads to that decision.",
        ),
        FieldSpec(
            name="evidence",
            kind=FieldKind.OBJECT_ARRAY,
            description="The supplied items the decision rests on.",
            spec=EVIDENCE_SPEC,
        ),
    ),
)

GENERATED_MAPPING_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="MappingClaim",
    description="One ATT&CK mapping claimed for the generated rule, with its evidence.",
    fields=(
        FieldSpec(
            name="tactic_id",
            kind=FieldKind.STRING,
            description=(
                "The tactic identifier, from the supplied MITRE material only. Empty string "
                "where the supplied material establishes none."
            ),
            allow_empty=True,
        ),
        FieldSpec(
            name="technique_id",
            kind=FieldKind.STRING,
            description="The technique identifier, from the supplied MITRE material only.",
        ),
        FieldSpec(
            name="support",
            kind=FieldKind.STRING,
            description="How well the supplied context supports this mapping.",
            enum=_values(SupportLevel),
        ),
        FieldSpec(
            name="evidence",
            kind=FieldKind.OBJECT_ARRAY,
            description="The supplied items establishing the mapping.",
            spec=EVIDENCE_SPEC,
        ),
    ),
)


def _envelope(operation: ReasoningOperation) -> tuple[FieldSpec, ...]:
    """Return the shared envelope fields, in the order ``shared/output.md`` states them."""
    return (
        FieldSpec(
            name="operation",
            kind=FieldKind.STRING,
            description="The operation you were asked to perform.",
            const=operation.value,
        ),
        FieldSpec(
            name="summary",
            kind=FieldKind.STRING,
            description="What you concluded, in one paragraph on a single line.",
        ),
        FieldSpec(
            name="findings",
            kind=FieldKind.OBJECT_ARRAY,
            description="Observations about the rule as it currently stands.",
            spec=FINDING_SPEC,
        ),
        FieldSpec(
            name="recommendations",
            kind=FieldKind.OBJECT_ARRAY,
            description="Changes that would improve the rule.",
            spec=RECOMMENDATION_SPEC,
        ),
        FieldSpec(
            name="confidence",
            kind=FieldKind.NUMBER,
            description=(
                "How well the supplied context supported your conclusions, from 0.0 to 1.0. "
                "Not a judgement of the rule's quality."
            ),
            minimum=0.0,
            maximum=1.0,
        ),
        FieldSpec(
            name="metadata",
            kind=FieldKind.STRING_MAP,
            description="Additional structured detail as string values. Empty object if none.",
        ),
        FieldSpec(
            name="uncertainties",
            kind=FieldKind.OBJECT_ARRAY,
            description=(
                "Every identifier the supplied context reports as unresolved or ambiguous. "
                "Carry each one forward with the status the context gave it."
            ),
            spec=UNCERTAINTY_SPEC,
        ),
    )


ANALYZE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="AnalyzeResponse",
    description=(
        "The assessment of the supplied rule. Report what is wrong with it, what it misses "
        "and how it can be evaded. Do not rewrite the rule."
    ),
    fields=_envelope(ReasoningOperation.ANALYZE),
)

ENHANCE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="EnhanceResponse",
    description=(
        "The improved rule, together with the weaknesses it answers and an accounting of "
        "every change. findings carry the weaknesses identified in the original rule; "
        "recommendations carry the problems the supplied context did not support fixing."
    ),
    fields=(
        *_envelope(ReasoningOperation.ENHANCE),
        FieldSpec(
            name="original_rule",
            kind=FieldKind.OBJECT,
            description="The rule as supplied, so the two versions can be compared.",
            spec=ORIGINAL_RULE_SPEC,
        ),
        FieldSpec(
            name="enhanced_rule",
            kind=FieldKind.OBJECT,
            description=(
                "The improved rule, complete and deployable. It must detect the same "
                "behaviour as the original."
            ),
            spec=RULE_SPEC,
        ),
        FieldSpec(
            name="changes",
            kind=FieldKind.OBJECT_ARRAY,
            description=(
                "One entry per change made, each tracing to a specific problem in the "
                "original rule."
            ),
            spec=CHANGE_SPEC,
            min_items=1,
        ),
    ),
)

GENERATE_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="GenerateResponse",
    description=(
        "The rule written for the supplied requirement, with the reasoning behind it. "
        "findings carry ambiguities in the requirement and limits of the supplied material; "
        "recommendations carry behaviours the requirement described that this rule does not "
        "cover."
    ),
    fields=(
        *_envelope(ReasoningOperation.GENERATE),
        FieldSpec(
            name="generated_rule",
            kind=FieldKind.OBJECT,
            description="The rule satisfying the requirement, complete and deployable.",
            spec=RULE_SPEC,
        ),
        FieldSpec(
            name="rationale",
            kind=FieldKind.OBJECT_ARRAY,
            description="One entry per authoring decision, in the order the decisions were made.",
            spec=RATIONALE_SPEC,
            min_items=1,
        ),
        FieldSpec(
            name="mappings",
            kind=FieldKind.OBJECT_ARRAY,
            description=(
                "The ATT&CK mappings claimed for the generated rule, each with the supplied "
                "material establishing it. Empty array where the material supports none."
            ),
            spec=GENERATED_MAPPING_SPEC,
        ),
    ),
)

OPERATION_SPECS: Final[Mapping[ReasoningOperation, ObjectSpec]] = MappingProxyType(
    {
        ReasoningOperation.ANALYZE: ANALYZE_SPEC,
        ReasoningOperation.ENHANCE: ENHANCE_SPEC,
        ReasoningOperation.GENERATE: GENERATE_SPEC,
    }
)
"""The response specification of each operation."""


def spec_for(operation: ReasoningOperation) -> ObjectSpec:
    """Return the response specification of one operation."""
    return OPERATION_SPECS[operation]


def output_format_for(operation: ReasoningOperation) -> str:
    """Return the ``{{OUTPUT_FORMAT}}`` text for one operation."""
    return render_object_spec(spec_for(operation))


def json_schema_for(operation: ReasoningOperation) -> Mapping[str, JSONValue]:
    """Return one operation's contract as a JSON Schema document.

    Handed to the LLM layer as plain JSON so a provider that can constrain its
    own decoding is told the shape rather than merely asked for it. Generated
    from the same specification as the prompt text and the validator, so all
    three state one contract.
    """
    return json_schema(spec_for(operation))
