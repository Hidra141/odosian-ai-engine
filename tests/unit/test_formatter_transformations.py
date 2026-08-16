"""Stage-17 deterministic transformations.

The rating table and the four contract normalisations, tested at their edges.

These are the only places Stage-17 decides anything. Everything else is a
rename, so if a boundary here is wrong the error is silent — a 94 quietly
becoming an ``A`` looks exactly like a 94 correctly becoming a ``B``.
"""

from __future__ import annotations

import pytest

from src.core.models import MappingClaim, MitreMapping, RuleChange
from src.core.types import (
    ChangeCategory,
    FalsePositiveRisk,
    FindingCategory,
    ImportanceLevel,
    OutputLanguage,
    SupportLevel,
)
from src.formatter import (
    ScoreOutOfRangeError,
    attack_mapping,
    change_label,
    confidence,
    finding_category,
    fp_risk,
    language,
    priority,
    rating_from_score,
)

# the rating bands, at every boundary the contract fixes


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100, "A+"),
        (95, "A+"),
        (94, "A"),
        (85, "A"),
        (84, "B"),
        (70, "B"),
        (69, "C"),
        (50, "C"),
        (49, "D"),
        (30, "D"),
        (29, "F"),
        (0, "F"),
    ],
)
def test_every_rating_boundary_is_exact(score, expected):
    assert rating_from_score(score) == expected


@pytest.mark.parametrize("score", [-1, -100, 101, 140, 1000])
def test_a_score_outside_the_scale_is_refused_not_clamped(score):
    """Refusing matches every other layer; clamping would invent a grade."""
    with pytest.raises(ScoreOutOfRangeError) as error:
        rating_from_score(score)
    assert error.value.score == score


@pytest.mark.parametrize("value", [True, False, 50.0, "50", None])
def test_a_score_that_is_not_an_integer_is_refused(value):
    with pytest.raises(ScoreOutOfRangeError):
        rating_from_score(value)


def test_the_whole_scale_is_covered_with_no_gap_and_no_overlap():
    letters = [rating_from_score(score) for score in range(0, 101)]
    assert set(letters) == {"A+", "A", "B", "C", "D", "F"}
    counts = {letter: letters.count(letter) for letter in set(letters)}
    assert counts == {"F": 30, "D": 20, "C": 20, "B": 15, "A": 10, "A+": 6}


# 1 — false-positive risk


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (FalsePositiveRisk.CRITICAL, "high"),
        (FalsePositiveRisk.HIGH, "high"),
        (FalsePositiveRisk.MEDIUM, "medium"),
        (FalsePositiveRisk.LOW, "low"),
    ],
)
def test_false_positive_risk_lands_inside_the_contract_scale(value, expected):
    assert fp_risk(value) == expected


def test_every_internal_risk_level_has_a_contract_value():
    assert {fp_risk(level) for level in FalsePositiveRisk} <= {"low", "medium", "high"}


# 2 — finding categories


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (FindingCategory.LOGIC, "logic_error"),
        (FindingCategory.FIELDS, "ecs_compliance"),
        (FindingCategory.FALSE_POSITIVES, "false_positive"),
        (FindingCategory.FALSE_NEGATIVES, "detection_gap"),
        (FindingCategory.EVASION, "detection_gap"),
        (FindingCategory.BRITTLENESS, "detection_gap"),
        (FindingCategory.MITRE_COVERAGE, "coverage_gap"),
        (FindingCategory.NOISE, "false_positive"),
        (FindingCategory.DOCUMENTATION, "metadata_issue"),
    ],
)
def test_every_finding_category_maps_as_frozen(value, expected):
    assert finding_category(value) == expected


def test_no_finding_category_escapes_the_contract_enum():
    contract = {
        "detection_gap",
        "false_positive",
        "performance",
        "ecs_compliance",
        "logic_error",
        "coverage_gap",
        "metadata_issue",
    }
    assert {finding_category(c) for c in FindingCategory} <= contract


# 3 — suggestion priority


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (ImportanceLevel.CRITICAL, 1),
        (ImportanceLevel.HIGH, 2),
        (ImportanceLevel.MEDIUM, 3),
        (ImportanceLevel.LOW, 4),
    ],
)
def test_priority_ranks_as_frozen(value, expected):
    assert priority(value) == expected


def test_priority_preserves_the_importance_ordering():
    ranks = [priority(level) for level in ImportanceLevel]
    assert ranks == sorted(ranks)


# 4 — changelog labels


def _change(before: str, after: str) -> RuleChange:
    return RuleChange(
        change_id="C1",
        category=ChangeCategory.CORRECTNESS,
        before=before,
        after=after,
        rationale="because the supplied material says so",
        addresses=(),
        evidence=(),
        support=SupportLevel.SUPPORTED,
    )


def test_a_change_that_adds_is_labelled_as_added():
    assert change_label(_change("", "process.parent.name : *")) == (
        "Added process.parent.name : *"
    )


def test_a_change_that_removes_is_labelled_as_removed():
    assert change_label(_change("process.args : *", "")) == "Removed process.args : *"


def test_a_change_that_replaces_names_both_sides():
    assert change_label(_change("a", "b")) == "Changed a to b"


def test_a_label_ignores_surrounding_whitespace():
    assert change_label(_change("   ", " b ")) == "Added b"


# language and confidence


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (OutputLanguage.KQL, "kuery"),
        (OutputLanguage.EQL, "eql"),
        (OutputLanguage.ESQL, "esql"),
        (OutputLanguage.LUCENE, "lucene"),
    ],
)
def test_query_languages_use_the_stored_value(value, expected):
    assert language(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"), [(0.0, 0), (0.5, 50), (0.83, 83), (1.0, 100), (0.75, 75)]
)
def test_confidence_becomes_the_contract_percentage(value, expected):
    assert confidence(value) == expected


# MITRE parent / sub-technique


def _claim(**changes) -> MappingClaim:
    base = {
        "tactic_id": "TA0002",
        "technique_id": "T1059.001",
        "support": SupportLevel.SUPPORTED,
        "evidence": (),
        "tactic_name": "Execution",
        "technique_name": "PowerShell",
        "confidence": 0.9,
    }
    return MappingClaim(**{**base, **changes})


def test_a_supplied_parent_becomes_the_technique_and_the_cited_one_the_sub():
    mapped = attack_mapping(
        _claim(
            parent_technique_id="T1059",
            parent_technique_name="Command and Scripting Interpreter",
        )
    )
    assert mapped["techniqueId"] == "T1059"
    assert mapped["techniqueName"] == "Command and Scripting Interpreter"
    assert mapped["subTechniqueId"] == "T1059.001"
    assert mapped["subTechniqueName"] == "PowerShell"


def test_without_a_parent_the_sub_technique_fields_are_null():
    """The contract's own representation for a mapping that names no sub-technique."""
    mapped = attack_mapping(_claim())
    assert mapped["techniqueId"] == "T1059.001"
    assert mapped["subTechniqueId"] is None
    assert mapped["subTechniqueName"] is None


def test_a_parent_is_never_derived_by_truncating_an_identifier():
    mapped = attack_mapping(_claim(technique_id="T1059.001", parent_technique_id=""))
    assert mapped["techniqueId"] == "T1059.001"
    assert mapped["subTechniqueId"] is None


def test_a_rule_mapping_is_shaped_the_same_way_as_a_claim():
    mapped = attack_mapping(
        MitreMapping(
            tactic_id="TA0002",
            technique_id="T1059.001",
            tactic_name="Execution",
            technique_name="PowerShell",
            confidence=0.65,
            parent_technique_id="T1059",
            parent_technique_name="Command and Scripting Interpreter",
        )
    )
    assert list(mapped) == [
        "tacticId",
        "tacticName",
        "techniqueId",
        "techniqueName",
        "subTechniqueId",
        "subTechniqueName",
        "confidence",
    ]
    assert mapped["confidence"] == 65
