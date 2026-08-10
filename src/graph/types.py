"""Knowledge graph types.

The vocabulary of what a node can be, what an edge can mean, and how an edge
came to exist.

Node and relationship types are declared whether or not the current corpus can
populate them. A type that yields no edges is reported as zero rather than
omitted: the absence is a fact about this snapshot of the data, and hiding the
type would make that absence invisible.
"""

from __future__ import annotations

from enum import StrEnum


class NodeType(StrEnum):
    """The kind of thing a node represents."""

    TECHNIQUE = "Technique"
    TACTIC = "Tactic"
    SOFTWARE = "Software"
    GROUP = "Group"
    MITIGATION = "Mitigation"
    CAMPAIGN = "Campaign"
    DATA_SOURCE = "DataSource"
    ECS_FIELD = "ECSField"
    LOLBAS_ENTRY = "LOLBASEntry"
    RULE = "Rule"
    TAG = "Tag"
    EXTERNAL_REFERENCE = "ExternalReference"


class RuleCategory(StrEnum):
    """Which rule corpus a :attr:`NodeType.RULE` node came from.

    Sigma and Elastic rules share one node type and are told apart by this
    property, because they are the same concept expressed by two projects.
    Splitting them into separate labels would duplicate every query.
    """

    SIGMA = "sigma"
    ELASTIC = "elastic"


class RelationshipType(StrEnum):
    """The meaning of an edge."""

    DETECTS = "DETECTS"
    """A rule names a technique in a dedicated detection field."""

    REFERENCES = "REFERENCES"
    """A record mentions a target somewhere other than a detection field."""

    USES_FIELD = "USES_FIELD"
    """A rule matches on a schema field."""

    HAS_TAG = "HAS_TAG"
    """A record carries a tag."""

    BELONGS_TO = "BELONGS_TO"
    """A technique belongs to a tactic."""

    SUBTECHNIQUE_OF = "SUBTECHNIQUE_OF"
    """A sub-technique refines a parent technique."""

    USES = "USES"
    """An actor, campaign or piece of software uses a technique."""

    MITIGATES = "MITIGATES"
    """A mitigation addresses a technique."""

    OBSERVES = "OBSERVES"
    """A data source observes a technique."""


class EdgeOrigin(StrEnum):
    """How the evidence for an edge was obtained."""

    RESOLVED_REFERENCE = "resolved_reference"
    """A reference read from metadata and resolved by the Stage-11 resolver."""

    LITERAL_METADATA = "literal_metadata"
    """A value read straight from metadata that needs no corpus lookup."""


class SkipReason(StrEnum):
    """Why a candidate edge was not created."""

    UNRESOLVED_TARGET = "unresolved_target"
    """The Stage-11 resolver found no record for the reference."""

    AMBIGUOUS_TARGET = "ambiguous_target"
    """The resolver found several records and none was chosen."""

    TARGET_NODE_ABSENT = "target_node_absent"
    """The resolved record produced no node of a usable type."""
