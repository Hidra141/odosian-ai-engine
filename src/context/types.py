"""Context vocabulary.

The sections a context package is built from, the kinds of evidence it carries,
and how evidence is prioritised when it will not all fit.

The enum naming avoids one collision worth calling out: the *name* of a section
is :class:`SectionName` here, while :class:`~src.context.models.ContextSection`
in the models module is the populated section itself. One is a label, the other
is a container of items, and giving both the same name would make every type
annotation ambiguous.

Nothing in this vocabulary expresses a judgement. There is no "malicious", no
"applies", no "recommended". A section says where evidence sits; a status says
what the retrieval layer established about it. Interpretation is Stage-15's.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class ContextOperation(StrEnum):
    """The engine operation a context package is being built for.

    Mirrors Stage-06's ``PromptOperation`` without importing it, so the context
    layer stays usable without the prompt package loaded.
    """

    ANALYZE = "analyze"
    ENHANCE = "enhance"
    GENERATE = "generate"


class SectionName(StrEnum):
    """A named part of the context package."""

    RULE = "rule"
    ENTITIES = "entities"
    MAPPINGS = "mappings"
    RETRIEVAL = "retrieval"
    GRAPH = "graph"
    KNOWLEDGE = "knowledge"
    REFERENCES = "references"
    WARNINGS = "warnings"
    METADATA = "metadata"


SECTION_ORDER: tuple[SectionName, ...] = (
    SectionName.RULE,
    SectionName.ENTITIES,
    SectionName.MAPPINGS,
    SectionName.RETRIEVAL,
    SectionName.GRAPH,
    SectionName.KNOWLEDGE,
    SectionName.REFERENCES,
    SectionName.WARNINGS,
    SectionName.METADATA,
)
"""The fixed order sections appear in. Ordering never depends on content."""


class EvidenceKind(StrEnum):
    """What a context item holds."""

    RULE_TEXT = "rule_text"
    RULE_DETECTION = "rule_detection"
    EXTRACTED_ENTITY = "extracted_entity"
    MAPPED_ENTITY = "mapped_entity"
    RETRIEVED_TEXT = "retrieved_text"
    RETRIEVED_GRAPH = "retrieved_graph"
    SEED_RESOLUTION = "seed_resolution"
    REFERENCE = "reference"
    WARNING = "warning"
    METADATA = "metadata"


class EvidenceStatus(StrEnum):
    """What the upstream layers established about a piece of evidence."""

    RESOLVED = "resolved"
    """An identifier resolved to exactly one knowledge record."""

    UNRESOLVED = "unresolved"
    """An identifier resolved to nothing. It is carried, never converted."""

    AMBIGUOUS = "ambiguous"
    """An identifier matched several records and none was chosen."""

    REDIRECTED = "redirected"
    """A deprecated identifier reached a record through ATT&CK's own successor.

    Settled, because a record was reached, but not ``resolved``: the identifier
    the rule wrote matched nothing, and what matched is the identifier ATT&CK
    revoked it in favour of. Both are carried, so the distinction survives into
    the prompt.
    """

    NOT_APPLICABLE = "not_applicable"
    """The item carries no identifier for which resolution is meaningful."""

    @property
    def is_resolved(self) -> bool:
        """Return whether this status asserts a single established target."""
        return self is EvidenceStatus.RESOLVED


class EvidencePriority(IntEnum):
    """Ordering class for evidence. Lower sorts first.

    The classes follow the precedence the retrieval layer already justifies: an
    exact identifier is a fact, a graph path is a stated relationship, an entity
    match is an agreement, and lexical overlap is a hint. Within a class the
    order Stage-13 produced is preserved verbatim — no score is recomputed here.
    """

    EXACT_IDENTIFIER = 0
    GRAPH = 1
    ENTITY_MATCH = 2
    LEXICAL = 3
    UNSPECIFIED = 4


class TruncationPolicy(StrEnum):
    """How a package is reduced when it will not fit its budget."""

    NONE = "none"
    """Refuse to reduce. Over-budget content raises instead."""

    TRIM_TAIL = "trim_tail"
    """Cut the tail of the item that crosses the limit, keeping earlier items whole."""

    DROP_LOWEST_PRIORITY = "drop_lowest_priority"
    """Drop whole items from the end of the ordering until the package fits."""


class WarningCode(StrEnum):
    """Why a warning was raised during construction."""

    SECTION_BUDGET_EXCEEDED = "section_budget_exceeded"
    TOTAL_BUDGET_EXCEEDED = "total_budget_exceeded"
    ITEM_TRUNCATED = "item_truncated"
    ITEM_DROPPED = "item_dropped"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    AMBIGUOUS_REFERENCE = "ambiguous_reference"
    REDIRECTED_REFERENCE = "redirected_reference"
    CREDENTIAL_REDACTED = "credential_redacted"
    EMPTY_RETRIEVAL = "empty_retrieval"
