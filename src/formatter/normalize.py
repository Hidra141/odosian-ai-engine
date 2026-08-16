"""Contract normalisations.

The deterministic conversions between the engine's vocabulary and the API's.

Each one is a fixed table or a fixed rule. None consults a model, reads a
dataset, or decides anything: given the same input they return the same output,
which is what makes them safe to sit outside the validation boundary.

Where a conversion loses information it is said so on the function, because a
lossy step that looks lossless is how a contract quietly stops meaning what it
says.
"""

from __future__ import annotations

from typing import Final

from src.core.models import MappingClaim, MitreMapping, RuleChange
from src.core.types import (
    FalsePositiveRisk,
    FindingCategory,
    ImportanceLevel,
    OutputLanguage,
)

FP_RISK: Final[dict[FalsePositiveRisk, str]] = {
    FalsePositiveRisk.CRITICAL: "high",
    FalsePositiveRisk.HIGH: "high",
    FalsePositiveRisk.MEDIUM: "medium",
    FalsePositiveRisk.LOW: "low",
}
"""The engine's four risk levels onto the contract's three.

Lossy in one place, and deliberately so: the contract admits no level above
``high``, so ``critical`` is carried to the highest level the contract has. The
engine keeps all four, and the distinction survives internally — it is only the
external document that cannot express it.
"""

FINDING_CATEGORY: Final[dict[FindingCategory, str]] = {
    FindingCategory.LOGIC: "logic_error",
    FindingCategory.FIELDS: "ecs_compliance",
    FindingCategory.FALSE_POSITIVES: "false_positive",
    FindingCategory.FALSE_NEGATIVES: "detection_gap",
    FindingCategory.EVASION: "detection_gap",
    FindingCategory.BRITTLENESS: "detection_gap",
    FindingCategory.MITRE_COVERAGE: "coverage_gap",
    FindingCategory.NOISE: "false_positive",
    FindingCategory.DOCUMENTATION: "metadata_issue",
}
"""The engine's nine analysis dimensions onto the contract's seven categories.

Several dimensions share a destination because they describe one outcome by
different routes: a missed variant, a cheap evasion and a brittle literal all
end as behaviour the rule does not catch.

``noise`` is the one imprecise entry. The engine asks whether a rule fires at a
volume an analyst can work; the contract's nearest category is the benign
matching that usually causes it. A rule that is noisy on true positives is
therefore filed slightly wrong, and the contract has no better home for it.
"""

PRIORITY: Final[dict[ImportanceLevel, int]] = {
    ImportanceLevel.CRITICAL: 1,
    ImportanceLevel.HIGH: 2,
    ImportanceLevel.MEDIUM: 3,
    ImportanceLevel.LOW: 4,
}
"""Importance onto the contract's rank, where 1 is highest.

Order-preserving: the enum is declared most-important first, and the ranks
follow that order, so a reader sorting by rank gets the order the engine meant.
"""

LANGUAGE: Final[dict[OutputLanguage, str]] = {
    OutputLanguage.KQL: "kuery",
    OutputLanguage.EQL: "eql",
    OutputLanguage.ESQL: "esql",
    OutputLanguage.LUCENE: "lucene",
}
"""Query languages onto the values the API stores.

Only one differs: the engine says ``kql`` and the API stores ``kuery`` for the
same language. The rest are identical and are listed anyway, so a language
added later cannot pass through unconsidered.
"""

CONFIDENCE_SCALE: Final[int] = 100
"""The contract states a mapping's confidence as a percentage of the engine's 0.0-1.0."""


def fp_risk(value: FalsePositiveRisk) -> str:
    """Return the contract's false-positive risk for an engine risk level."""
    return FP_RISK[value]


def finding_category(value: FindingCategory) -> str:
    """Return the contract's finding category for an engine dimension."""
    return FINDING_CATEGORY[value]


def priority(value: ImportanceLevel) -> int:
    """Return the contract's numeric priority for an engine importance."""
    return PRIORITY[value]


def language(value: OutputLanguage) -> str:
    """Return the value the API stores for an engine query language."""
    return LANGUAGE[value]


def confidence(value: float) -> int:
    """Return a 0.0-1.0 mapping confidence as the contract's 0-100 integer."""
    return round(value * CONFIDENCE_SCALE)


def change_label(change: RuleChange) -> str:
    """Return a one-line label for a change, built from what it replaced.

    Derived rather than written, because no model is asked for a label and this
    layer invents no prose. The three cases are the three shapes a change takes:
    something added, something removed, something replaced.
    """
    before = change.before.strip()
    after = change.after.strip()
    if not before:
        return f"Added {after}"
    if not after:
        return f"Removed {before}"
    return f"Changed {before} to {after}"


def attack_mapping(mapping: MappingClaim | MitreMapping) -> dict[str, object]:
    """Return one ATT&CK mapping in the contract's shape.

    The contract separates a technique from its sub-technique; the engine keeps
    the cited identifier together with the parent it was given. Where a parent
    was supplied, it becomes the technique and the cited one becomes the
    sub-technique. Where none was supplied, the cited identifier is the
    technique and the sub-technique fields are ``null`` — the contract's own
    representation for a mapping that names no sub-technique.

    Nothing is derived by truncating an identifier: a parent absent from the
    supplied material stays absent here.
    """
    parent = mapping.parent_technique_id.strip()
    if parent:
        technique_id: str = parent
        technique_name: str = mapping.parent_technique_name
        sub_id: str | None = mapping.technique_id
        sub_name: str | None = mapping.technique_name
    else:
        technique_id = mapping.technique_id
        technique_name = mapping.technique_name
        sub_id = None
        sub_name = None
    return {
        "tacticId": mapping.tactic_id,
        "tacticName": mapping.tactic_name,
        "techniqueId": technique_id,
        "techniqueName": technique_name,
        "subTechniqueId": sub_id,
        "subTechniqueName": sub_name,
        "confidence": confidence(mapping.confidence),
    }
