"""Reasoning vocabulary.

The operations the engine performs, the categories its results are expressed
in, and the names of the prompt variables it fills.

Every enumeration here is a *closed* vocabulary: a value outside it is a
validation failure rather than an unknown member. That is deliberate and it is
the difference between this layer and the parsing layers upstream. A rule that
carries an unfamiliar severity label is still a rule worth reasoning about, so
Stage-08 keeps an ``UNKNOWN`` member for it. A model that answers with an
unfamiliar severity has not answered the question it was asked, so Stage-15
rejects it.

Nothing here judges evidence. :class:`SupportLevel` and
:class:`UncertaintyStatus` record what the supplied context established, in the
same three-way distinction the context layer and ``prompts/shared/safety.md``
already use.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from src.context.types import ContextOperation
from src.knowledge.models.types import KnowledgeSource
from src.prompts.types import PromptOperation


class ReasoningOperation(StrEnum):
    """An operation the reasoning engine can be asked to perform.

    The three operations of Stage-06 and Stage-14, named once more here so the
    core layer has its own vocabulary rather than borrowing the prompt layer's.
    There is no ``explain`` operation.
    """

    ANALYZE = "analyze"
    ENHANCE = "enhance"
    GENERATE = "generate"

    @property
    def prompt_operation(self) -> PromptOperation:
        """Return the prompt operation selecting this operation's templates."""
        return PromptOperation(self.value)

    @property
    def context_operation(self) -> ContextOperation:
        """Return the context operation a package for this operation carries."""
        return ContextOperation(self.value)

    @classmethod
    def from_context(cls, operation: ContextOperation) -> ReasoningOperation:
        """Return the reasoning operation matching a context operation."""
        return cls(operation.value)


class FindingCategory(StrEnum):
    """The dimension a finding speaks about.

    The nine dimensions ``prompts/analyze/instruction.md`` asks the model to
    work through, in that order.
    """

    LOGIC = "logic"
    FIELDS = "fields"
    FALSE_POSITIVES = "false_positives"
    FALSE_NEGATIVES = "false_negatives"
    EVASION = "evasion"
    BRITTLENESS = "brittleness"
    MITRE_COVERAGE = "mitre_coverage"
    NOISE = "noise"
    DOCUMENTATION = "documentation"


class ImportanceLevel(StrEnum):
    """How much a finding or a recommendation matters.

    The four levels ``prompts/shared/glossary.md`` fixes for severity. Reused
    for a recommendation's priority so the two orderings stay comparable.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FalsePositiveRisk(StrEnum):
    """How likely the rule is to fire on benign activity.

    A property of the rule, not of the analysis. It shares its four values with
    :class:`ImportanceLevel` but is kept separate because the two answer
    different questions: how noisy the rule is, against how much a finding
    matters. Collapsing them would make a change to either silently change the
    other.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SupportLevel(StrEnum):
    """How well the supplied context supports a claim.

    The three degrees of support ``prompts/shared/safety.md`` defines. They are
    never blurred: a claim the context points toward is not a claim the context
    establishes.
    """

    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    UNSUPPORTED = "unsupported"


class UncertaintyStatus(StrEnum):
    """The unresolved state of an identifier, carried forward unchanged.

    Deliberately narrower than the context layer's ``EvidenceStatus``: only the
    two states that must survive reasoning appear here. ``resolved`` is absent
    because a resolved identifier is not an uncertainty, and allowing the value
    would let a response declare an unresolved identifier settled.
    """

    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"


class EvidenceSource(StrEnum):
    """Where a cited piece of evidence sits in the supplied package."""

    MITRE = "mitre"
    SIGMA = "sigma"
    ELASTIC = "elastic"
    LOLBAS = "lolbas"
    ECS = "ecs"
    RULE = "rule"
    ENTITIES = "entities"
    CONTEXT = "context"

    @classmethod
    def from_knowledge_source(cls, source: KnowledgeSource) -> EvidenceSource:
        """Return the citation source naming one knowledge dataset."""
        return cls(source.value)


class OutputSeverity(StrEnum):
    """The severity a produced rule declares.

    The four values of ``prompts/shared/glossary.md``. Narrower than Stage-08's
    ``RuleSeverity``, which also carries ``informational`` and ``unknown``: a
    rule the engine writes must commit to one of the four.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class OutputLanguage(StrEnum):
    """The query language a produced rule is written in.

    Spelled as the glossary spells them for the model. ``Stage-08``'s
    ``RuleLanguage.from_value`` accepts every one of these tokens, so a result
    converts into the parser's vocabulary without a translation table here.
    """

    KQL = "kql"
    EQL = "eql"
    ESQL = "esql"
    LUCENE = "lucene"


class OutputRuleType(StrEnum):
    """The rule type a produced rule declares."""

    QUERY = "query"
    THRESHOLD = "threshold"
    EQL = "eql"
    NEW_TERMS = "new_terms"
    ESQL = "esql"


class ChangeCategory(StrEnum):
    """What an enhancement change was made for.

    The five improvement priorities of ``prompts/enhance/instruction.md``, plus
    ``metadata`` for the correction its constraints section requires when
    severity, risk score or mapping no longer matches the improved query.
    """

    CORRECTNESS = "correctness"
    EVASION_RESISTANCE = "evasion_resistance"
    FALSE_POSITIVE_REDUCTION = "false_positive_reduction"
    COVERAGE = "coverage"
    DOCUMENTATION = "documentation"
    METADATA = "metadata"


class RationaleAspect(StrEnum):
    """The authoring decision a piece of generation rationale accounts for.

    The six steps of ``prompts/generate/instruction.md``, in that order.
    """

    TARGET_BEHAVIOUR = "target_behaviour"
    DATA_SOURCE = "data_source"
    QUERY_LANGUAGE = "query_language"
    QUERY_LOGIC = "query_logic"
    METADATA = "metadata"
    DOCUMENTATION = "documentation"


PROMPT_VARIABLE_RULE: Final[str] = "RULE"
PROMPT_VARIABLE_CONTEXT: Final[str] = "CONTEXT"
PROMPT_VARIABLE_ENTITIES: Final[str] = "ENTITIES"
PROMPT_VARIABLE_MITRE: Final[str] = "MITRE"
PROMPT_VARIABLE_SIGMA: Final[str] = "SIGMA"
PROMPT_VARIABLE_ELASTIC: Final[str] = "ELASTIC"
PROMPT_VARIABLE_ATOMIC: Final[str] = "ATOMIC"
PROMPT_VARIABLE_LOLBAS: Final[str] = "LOLBAS"
PROMPT_VARIABLE_SIMILAR_RULES: Final[str] = "SIMILAR_RULES"
PROMPT_VARIABLE_OUTPUT_FORMAT: Final[str] = "OUTPUT_FORMAT"

PROMPT_VARIABLES: Final[tuple[str, ...]] = (
    PROMPT_VARIABLE_RULE,
    PROMPT_VARIABLE_CONTEXT,
    PROMPT_VARIABLE_ENTITIES,
    PROMPT_VARIABLE_MITRE,
    PROMPT_VARIABLE_SIGMA,
    PROMPT_VARIABLE_ELASTIC,
    PROMPT_VARIABLE_ATOMIC,
    PROMPT_VARIABLE_LOLBAS,
    PROMPT_VARIABLE_SIMILAR_RULES,
    PROMPT_VARIABLE_OUTPUT_FORMAT,
)
"""Every variable Stage-15 supplies, in the order Prompt Specification v1.0 lists them."""

NO_MATERIAL: Final[str] = (
    "NONE SUPPLIED. No material of this kind is present in the context package. "
    "Treat this section as empty and do not supply its content from memory."
)
"""What a prompt variable renders as when the package carries nothing for it.

An empty string would read as an omission the model may fill in. This states the
absence, so a gap in the corpus arrives as a gap.
"""
