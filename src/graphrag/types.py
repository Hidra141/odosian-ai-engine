"""GraphRAG types.

The retrieval vocabulary: how a query is answered, what part of a record a chunk
came from, and how a candidate was found.

Sections are named from the labels the corpus actually writes. Where a record
uses a label this vocabulary does not recognise, the chunk keeps the source's
own wording and is typed :attr:`SectionType.OTHER` rather than being forced into
a section the record never had.
"""

from __future__ import annotations

from enum import StrEnum


class RetrievalMode(StrEnum):
    """How a query is answered."""

    TEXT = "text"
    GRAPH = "graph"
    HYBRID = "hybrid"


class RetrievalMethod(StrEnum):
    """The route by which a candidate was found."""

    TEXT = "text"
    GRAPH = "graph"


class SectionType(StrEnum):
    """The part of a record a chunk came from."""

    SUMMARY = "summary"
    METADATA = "metadata"
    DESCRIPTION = "description"
    DETECTION = "detection"
    QUERY = "query"
    CONDITION = "condition"
    COMMAND = "command"
    FALSE_POSITIVES = "false_positives"
    TAGS = "tags"
    REFERENCES = "references"
    PLATFORMS = "platforms"
    RELATIONSHIPS = "relationships"
    FIELD = "field"
    USAGE = "usage"
    OTHER = "other"


class MatchKind(StrEnum):
    """Why a candidate matched."""

    EXACT_IDENTIFIER = "exact_identifier"
    ENTITY = "entity"
    CANONICAL_FIELD = "canonical_field"
    LEXICAL = "lexical"
    GRAPH_SEED = "graph_seed"
    GRAPH_NEIGHBOUR = "graph_neighbour"


class SeedStatus(StrEnum):
    """What happened when a query entity was looked up in the graph."""

    RESOLVED = "resolved"
    """Exactly one node carries the identifier."""

    UNRESOLVED = "unresolved"
    """No node carries it. It is reported, never manufactured."""

    AMBIGUOUS = "ambiguous"
    """Several nodes carry it. All are reported and none is chosen."""

    REDIRECTED = "redirected"
    """No node carries it, but ATT&CK revoked it in favour of one that a node does.

    Deliberately not ``resolved``. The identifier the rule wrote reached nothing;
    what reached a node is ATT&CK's own successor for it, and the two facts stay
    apart. The report carries both identifiers, so no later stage has to guess
    which one the rule actually named.
    """
