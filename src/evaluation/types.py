"""Evaluation vocabulary.

Relevance grades, case categories, and the rules by which ground truth is
derived from the corpus.

Ground truth is *derived*, never hand-asserted and never produced by a model.
Each rule reads explicit metadata the datasets already carry, so a judgment can
be traced to the field that justifies it and re-derived byte-identically on any
machine.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Relevance(IntEnum):
    """Graded relevance of a record to a query."""

    IRRELEVANT = 0
    PARTIAL = 1
    RELEVANT = 2
    HIGHLY_RELEVANT = 3


class CaseCategory(StrEnum):
    """What kind of question a benchmark case asks."""

    EXACT_ATTACK_ID = "exact_attack_id"
    TECHNIQUE_NAME = "technique_name"
    DETECTION_BEHAVIOUR = "detection_behaviour"
    COMMAND_PROCESS = "command_process"
    NETWORK = "network"
    ECS_FIELD = "ecs_field"
    SIGMA_DETECTION = "sigma_detection"
    ELASTIC_DETECTION = "elastic_detection"
    LOLBAS = "lolbas"
    MULTI_ENTITY = "multi_entity"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    MISSING_TACTIC = "missing_tactic"
    AMBIGUOUS_REFERENCE = "ambiguous_reference"


class GroundTruthRule(StrEnum):
    """How a case's judgments are derived from the corpus."""

    ATTACK_TECHNIQUE = "attack_technique"
    """The MITRE record for the identifier, plus every record that cites it."""

    TECHNIQUE_NAME = "technique_name"
    """Every MITRE record whose name matches exactly, plus records citing them."""

    ECS_FIELD = "ecs_field"
    """The ECS record defining the field."""

    LOLBAS_BINARY = "lolbas_binary"
    """Every LOLBAS record for the binary."""

    CITING_RECORDS_ONLY = "citing_records_only"
    """Only the records that cite an identifier the corpus does not define."""

    ALL_CANDIDATES = "all_candidates"
    """Every record carrying an identifier, none preferred over another."""

    NONE_EXPECTED = "none_expected"
    """The corpus defines nothing for this identifier; no judgment is created."""


class AblationVariant(StrEnum):
    """A ranking configuration used only for comparison."""

    FULL = "full"
    NO_GRAPH = "no_graph"
    NO_EXACT_IDENTIFIER = "no_exact_identifier"
    NO_ENTITY_MATCH = "no_entity_match"
    NO_SOURCE_WEIGHT = "no_source_weight"
