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
    FalsePositiveRisk,
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
                "supplied material, in the form '<CONTEXT_ITEM_ID>'."
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
                "The identifier the item establishes, reproduced exactly as supplied — an "
                "ATT&CK identifier such as '<TECHNIQUE_ID>' or an ECS field such as "
                "'<ECS_FIELD>'. Empty string when the item carries none. Never write an "
                "identifier that does not occur in the supplied material."
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
        FieldSpec(
            name="code_snippet",
            kind=FieldKind.STRING,
            description=(
                "The query fragment that applies this recommendation. It may reference only "
                "fields and values the supplied material confirms, and may introduce no "
                "identifier the supplied material does not carry. Empty string where the "
                "change cannot be expressed as a fragment. This is the one field that may "
                "run to several lines: a fragment of more than a clause or two is written "
                "that way by every tool that produces one."
            ),
            allow_empty=True,
            allow_multiline=True,
        ),
    ),
)

_MITRE_NAME_FIELDS: Final[tuple[FieldSpec, ...]] = (
    FieldSpec(
        name="tactic_id",
        kind=FieldKind.STRING,
        description=(
            "The tactic identifier in official form, written as '<TACTIC_ID>'. Use only "
            "identifiers present in the supplied MITRE material. Empty string where the "
            "supplied material establishes none."
        ),
        allow_empty=True,
    ),
    FieldSpec(
        name="tactic_name",
        kind=FieldKind.STRING,
        description=(
            "The tactic's name, copied exactly from the supplied MITRE material that names "
            "it. Empty string where the supplied material carries the identifier but not the "
            "name, and where it carries neither. Never supply a name from your own knowledge: "
            "a name you were not given is a fabrication even when the identifier is correct."
        ),
        allow_empty=True,
    ),
    FieldSpec(
        name="technique_id",
        kind=FieldKind.STRING,
        description=(
            "The technique identifier in official form, written as '<TECHNIQUE_ID>'. Use only "
            "identifiers present in the supplied MITRE material."
        ),
    ),
    FieldSpec(
        name="technique_name",
        kind=FieldKind.STRING,
        description=(
            "The technique's name, copied exactly from the supplied MITRE material that names "
            "it. Empty string where the supplied material does not name it. Never supply a "
            "name from your own knowledge."
        ),
        allow_empty=True,
    ),
    FieldSpec(
        name="confidence",
        kind=FieldKind.NUMBER,
        description=(
            "How well the supplied material establishes this specific mapping, from 0.0 to "
            "1.0. This is about the mapping alone, not about the rule and not about your "
            "answer as a whole."
        ),
        minimum=0.0,
        maximum=1.0,
    ),
    FieldSpec(
        name="parent_technique_id",
        kind=FieldKind.STRING,
        description=(
            "When the technique above is a sub-technique, its parent technique's identifier, "
            "copied from the supplied material that states the parent. Empty string when the "
            "technique is not a sub-technique, and empty string when the material does not "
            "state the parent. Never derive a parent by truncating an identifier."
        ),
        allow_empty=True,
    ),
    FieldSpec(
        name="parent_technique_name",
        kind=FieldKind.STRING,
        description=(
            "The parent technique's name, copied exactly from the supplied material that "
            "names it. Empty string where the material does not name it. Like every other "
            "name here, it is copied and never recalled."
        ),
        allow_empty=True,
    ),
)
"""The ATT&CK identity a mapping states, shared by every mapping shape.

Declared once so a rule's mapping and a claimed mapping cannot drift apart, and
so the anti-fabrication wording is stated in exactly one place.
"""

MITRE_MAPPING_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="MitreMapping",
    description="One ATT&CK mapping a rule declares.",
    fields=_MITRE_NAME_FIELDS,
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
                "The complete query. Reference only fields the supplied "
                "material confirms exist."
            ),
            allow_multiline=True,
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
            name="tags",
            kind=FieldKind.STRING_ARRAY,
            description=(
                "Short labels classifying the rule — the platform, data source or behaviour "
                "it concerns. Each must be justified by the rule itself or by the supplied "
                "material. A tag is a classification, not an assertion of external fact: do "
                "not tag with a threat group, campaign or product the supplied material does "
                "not mention. Empty array where none is justified."
            ),
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
            description="The supplied rule's query, copied exactly.",
            allow_multiline=True,
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
    description="One ATT&CK mapping claimed for a rule, with the material establishing it.",
    fields=(
        *_MITRE_NAME_FIELDS,
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


EVASION_RISK_SPEC: Final[ObjectSpec] = ObjectSpec(
    name="EvasionRisk",
    description="One way an attacker could avoid this rule while still doing the thing.",
    fields=(
        FieldSpec(
            name="technique",
            kind=FieldKind.STRING,
            description=(
                "What the attacker changes, named in a few words — the abbreviation, flag, "
                "path or ordering they vary. It must be one the supplied material lists."
            ),
        ),
        FieldSpec(
            name="description",
            kind=FieldKind.STRING,
            description=(
                "Why that change defeats this rule, in one line, referring to the part of "
                "the query it slips past."
            ),
        ),
        FieldSpec(
            name="mitigation",
            kind=FieldKind.STRING,
            description=(
                "What would catch it instead, in one line. State only a change the supplied "
                "material supports; where the material suggests none, say that plainly "
                "rather than inventing one."
            ),
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
            description=(
                "Additional structured detail. Every value is a JSON string, even one that "
                "represents a number or count — write 3 as \"3\", not 3. Empty object if none."
            ),
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
    fields=(
        *_envelope(ReasoningOperation.ANALYZE),
        FieldSpec(
            name="score",
            kind=FieldKind.INTEGER,
            description=(
                "The rule's quality as a detection, from 0 to 100, where 100 is a rule with "
                "no weakness the supplied material reveals. This judges the rule, not your "
                "certainty: a well-supported assessment of a poor rule scores low. It must "
                "agree with your findings — a score above 70 alongside a critical finding is "
                "a contradiction."
            ),
            minimum=0,
            maximum=100,
        ),
        FieldSpec(
            name="fp_risk",
            kind=FieldKind.STRING,
            description=(
                "How likely this rule is to fire on benign activity, judged from the rule's "
                "own breadth and from what the supplied material says about the behaviour it "
                "matches."
            ),
            enum=_values(FalsePositiveRisk),
        ),
        FieldSpec(
            name="strengths",
            kind=FieldKind.STRING_ARRAY,
            description=(
                "What the rule does well, one item per strength, each in one line. State only "
                "strengths the rule text or the supplied material demonstrates. Empty array "
                "where the material shows none — an empty array is a real answer, and "
                "inventing a compliment is a fabrication like any other."
            ),
        ),
        FieldSpec(
            name="weaknesses",
            kind=FieldKind.STRING_ARRAY,
            description=(
                "The rule's shortcomings, one per item, each stated in one line as a plain "
                "shortcoming rather than a fix. This is a short account a reader can scan; "
                "it is not a restatement of the findings list and must not be produced by "
                "copying it. Say the weakness itself, not the evidence for it. Empty array "
                "where the supplied material shows none."
            ),
        ),
        FieldSpec(
            name="evasion_risks",
            kind=FieldKind.OBJECT_ARRAY,
            description=(
                "How an attacker could avoid this rule while still performing the behaviour "
                "it targets, one entry per route. Every route must rest on the rule's own "
                "logic or on the supplied material — an abbreviation, flag or alternative the "
                "material lists. Do not describe evasions from your own knowledge of the "
                "technique. Empty array where the material supports none."
            ),
            spec=EVASION_RISK_SPEC,
        ),
        FieldSpec(
            name="mappings",
            kind=FieldKind.OBJECT_ARRAY,
            description=(
                "The ATT&CK mappings the supplied material establishes for this rule, each "
                "with the items establishing it. Empty array where the material supports "
                "none. Do not map the rule to a technique the material does not carry."
            ),
            spec=GENERATED_MAPPING_SPEC,
        ),
    ),
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
        FieldSpec(
            name="score",
            kind=FieldKind.INTEGER,
            description=(
                "How good a detection the rule you just wrote is, from 0 to 100, judged "
                "against the requirement and the material you were given. Score the rule, not "
                "your certainty, and do not score it well because you wrote it: a rule the "
                "supplied material could not fully ground scores lower."
            ),
            minimum=0,
            maximum=100,
        ),
        FieldSpec(
            name="notes",
            kind=FieldKind.STRING,
            description=(
                "What a deployment should weigh before running this rule, in one line — the "
                "tuning, exclusion or follow-up you would advise next. This looks forward at "
                "what remains to be done, and is not a summary of what you already wrote. "
                "Empty string where the supplied material suggests nothing further."
            ),
            allow_empty=True,
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
