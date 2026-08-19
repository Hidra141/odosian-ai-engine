"""What the context says about a reference ATT&CK renumbered.

Stage-13 can now report a fourth thing about a seed: that the identifier the
rule wrote reached nothing, but the identifier ATT&CK revoked it in favour of
reached a record. Stage-14 has to carry that forward as the distinct fact it is.

Getting it wrong has two failure modes and they point in opposite directions.
Treating a redirect as *resolved* tells the model the rule cited a technique it
never cited — the rule said ``T1562.001`` and the package would show ``T1685``
established with no trace of the substitution. Treating it as *unresolved* is
the older behaviour and merely wasteful, but it is also now false: a record was
reached, and warning that the identifier "matched no knowledge record" would
contradict the evidence sitting beside it.

So the package carries both identifiers, its own status, its own warning code,
and a provenance entry pairing the two. The validator enforces that: an item
declaring ``redirected`` that has lost either half is an issue, because a
redirect missing the identifier it redirected to is indistinguishable from a
plain failure.
"""

from __future__ import annotations

from src.context.context_builder import ContextBuilder
from src.context.evidence import EvidenceExtractor
from src.context.models import (
    ContextItem,
    ContextPackage,
    ContextSection,
    ItemProvenance,
    RuleContext,
)
from src.context.types import (
    ContextOperation,
    EvidenceKind,
    EvidenceStatus,
    SectionName,
    WarningCode,
)
from src.context.validation import ContextValidator
from src.graphrag.models import RetrievalQuery, RetrievalResult
from src.graphrag.provenance import SeedReport
from src.graphrag.types import RetrievalMode

CONVERTER = EvidenceExtractor()
BUILDER = ContextBuilder()
VALIDATOR = ContextValidator()

RULE = RuleContext(title="Defender tampering", identifier="probe-0001")


def result(*seeds: SeedReport) -> RetrievalResult:
    """Return a retrieval result carrying only the seed reports a case states."""
    return RetrievalResult(
        query=RetrievalQuery(text="probe", entity_ids=tuple(item.value for item in seeds)),
        mode=RetrievalMode.HYBRID,
        seeds=seeds,
    )


def redirected(original: str = "T1562.001", successor: str = "T1685") -> SeedReport:
    """Return the report Stage-13 writes for a followed redirect."""
    return SeedReport(
        value=original,
        status="redirected",
        node_ids=(f"mitre:Technique:enterprise:{successor}",),
        note=f"ATT&CK revoked this identifier in favour of {successor}",
        resolved_value=successor,
    )


def resolved(identifier: str = "T1059.001") -> SeedReport:
    """Return the report Stage-13 writes for an identifier the corpus holds."""
    return SeedReport(
        value=identifier,
        status="resolved",
        node_ids=(f"mitre:Technique:enterprise:{identifier}",),
    )


def unresolved(identifier: str = "T9999") -> SeedReport:
    """Return the report Stage-13 writes for an identifier nothing carries."""
    return SeedReport(
        value=identifier,
        status="unresolved",
        note="no node carries this identifier",
    )


def seed_items(batch):
    """Return the seed-resolution items of a batch, in order."""
    return [item for item in batch.items if item.section is SectionName.KNOWLEDGE]


# ------------------------------------------------------------------ status


def test_a_redirected_seed_carries_its_own_evidence_status():
    item = seed_items(CONVERTER.from_seeds(result(redirected())))[0]
    assert item.evidence_status is EvidenceStatus.REDIRECTED


def test_a_redirected_seed_is_not_reported_resolved():
    item = seed_items(CONVERTER.from_seeds(result(redirected())))[0]
    assert item.evidence_status is not EvidenceStatus.RESOLVED
    assert not item.evidence_status.is_resolved


def test_a_redirected_seed_is_not_reported_unresolved():
    item = seed_items(CONVERTER.from_seeds(result(redirected())))[0]
    assert item.evidence_status is not EvidenceStatus.UNRESOLVED


def test_the_other_three_statuses_are_unchanged():
    batch = CONVERTER.from_seeds(result(resolved(), unresolved(), redirected()))
    assert [item.evidence_status for item in seed_items(batch)] == [
        EvidenceStatus.RESOLVED,
        EvidenceStatus.UNRESOLVED,
        EvidenceStatus.REDIRECTED,
    ]


# -------------------------------------------------------------- both halves


def test_the_original_identifier_survives_into_the_item():
    item = seed_items(CONVERTER.from_seeds(result(redirected())))[0]
    assert item.metadata["identifier"] == "T1562.001"
    assert item.provenance is not None
    assert item.provenance.matched_entities == ("T1562.001",)


def test_the_successor_is_recorded_separately():
    item = seed_items(CONVERTER.from_seeds(result(redirected())))[0]
    assert item.metadata["resolved_identifier"] == "T1685"


def test_the_rendered_text_names_both_identifiers():
    item = seed_items(CONVERTER.from_seeds(result(redirected())))[0]
    assert "T1562.001" in item.text
    assert "T1685" in item.text
    assert "redirected" in item.text


def test_a_resolved_seed_records_no_successor():
    item = seed_items(CONVERTER.from_seeds(result(resolved())))[0]
    assert item.metadata["resolved_identifier"] == ""


# ------------------------------------------------------------------ warning


def test_a_redirected_seed_raises_its_own_warning_code():
    batch = CONVERTER.from_seeds(result(redirected()))
    assert [warning.code for warning in batch.warnings] == [WarningCode.REDIRECTED_REFERENCE]


def test_the_warning_does_not_claim_the_reference_matched_nothing():
    batch = CONVERTER.from_seeds(result(redirected()))
    detail = batch.warnings[0].detail
    assert "matched no knowledge record" not in detail
    assert "deprecated" in detail
    assert "T1685" in detail


def test_an_unresolved_seed_keeps_the_unresolved_warning():
    batch = CONVERTER.from_seeds(result(unresolved()))
    assert [warning.code for warning in batch.warnings] == [WarningCode.UNRESOLVED_REFERENCE]


def test_a_resolved_seed_still_raises_no_warning():
    assert CONVERTER.from_seeds(result(resolved())).warnings == ()


# --------------------------------------------------------------- provenance


def test_the_package_provenance_pairs_the_original_with_the_successor():
    package = BUILDER.build(ContextOperation.ANALYZE, rule=RULE, retrieval=result(redirected()))
    assert package.provenance is not None
    assert package.provenance.redirected_identifiers == (("T1562.001", "T1685"),)


def test_a_collapse_keeps_every_original_in_the_package_provenance():
    package = BUILDER.build(
        ContextOperation.ANALYZE,
        rule=RULE,
        retrieval=result(
            redirected("T1562"), redirected("T1562.001"), redirected("T1562.006")
        ),
    )
    assert package.provenance is not None
    assert package.provenance.redirected_identifiers == (
        ("T1562", "T1685"),
        ("T1562.001", "T1685"),
        ("T1562.006", "T1685"),
    )


def test_a_redirected_identifier_is_not_listed_as_unresolved():
    package = BUILDER.build(
        ContextOperation.ANALYZE, rule=RULE, retrieval=result(redirected(), unresolved())
    )
    assert package.provenance is not None
    assert package.provenance.unresolved_identifiers == ("T9999",)
    assert package.provenance.ambiguous_identifiers == ()


def test_the_flattened_provenance_renders_the_pair():
    package = BUILDER.build(ContextOperation.ANALYZE, rule=RULE, retrieval=result(redirected()))
    assert package.provenance is not None
    assert package.provenance.as_mapping()["redirected_identifiers"] == "T1562.001->T1685"


def test_the_package_lists_its_redirected_items():
    package = BUILDER.build(
        ContextOperation.ANALYZE, rule=RULE, retrieval=result(redirected(), resolved())
    )
    assert [item.metadata["identifier"] for item in package.redirected_items] == ["T1562.001"]
    assert package.unresolved_items == ()


# --------------------------------------------------------------- validation


def test_a_well_formed_redirect_raises_no_validation_issue():
    package = BUILDER.build(ContextOperation.ANALYZE, rule=RULE, retrieval=result(redirected()))
    codes = {issue.check for issue in VALIDATOR.validate(package).issues}
    assert "redirected_reported_as_resolved" not in codes
    assert "redirect_successor_lost" not in codes
    assert "redirect_original_lost" not in codes


def malformed(**overrides) -> ContextPackage:
    """Return a package holding one seed item, built to a case's specification.

    Assembled by hand rather than by mutating a real package, so each case states
    exactly which half of the redirect it broke.
    """
    metadata = {
        "identifier": "T1562.001",
        "status": "redirected",
        "candidate_count": "1",
        "candidates": "mitre:Technique:enterprise:T1685",
        "resolved_identifier": "T1685",
        **overrides.pop("metadata", {}),
    }
    item = ContextItem(
        item_id="knowledge:0000",
        section=SectionName.KNOWLEDGE,
        kind=EvidenceKind.SEED_RESOLUTION,
        text="identifier T1562.001 -> T1685: redirected",
        evidence_status=overrides.pop("evidence_status", EvidenceStatus.REDIRECTED),
        provenance=ItemProvenance(origin="stage13:seed", matched_entities=("T1562.001",)),
        metadata=metadata,
    )
    return ContextPackage(
        operation=ContextOperation.ANALYZE,
        rule_context=RULE,
        sections=(ContextSection(name=SectionName.KNOWLEDGE, items=(item,)),),
    )


def test_the_hand_built_package_is_itself_clean():
    """The control: without an override, none of the three issues fires."""
    codes = {issue.check for issue in VALIDATOR.validate(malformed()).issues}
    assert not codes & {
        "redirected_reported_as_resolved",
        "redirect_successor_lost",
        "redirect_original_lost",
    }


def test_a_redirect_presented_as_resolved_is_an_issue():
    broken = malformed(evidence_status=EvidenceStatus.RESOLVED)
    codes = {issue.check for issue in VALIDATOR.validate(broken).issues}
    assert "redirected_reported_as_resolved" in codes


def test_a_redirect_that_lost_its_successor_is_an_issue():
    broken = malformed(metadata={"resolved_identifier": ""})
    codes = {issue.check for issue in VALIDATOR.validate(broken).issues}
    assert "redirect_successor_lost" in codes


def test_a_redirect_that_lost_its_original_is_an_issue():
    broken = malformed(metadata={"identifier": ""})
    codes = {issue.check for issue in VALIDATOR.validate(broken).issues}
    assert "redirect_original_lost" in codes


# ------------------------------------------------------------- uncertainties


def test_a_redirect_is_not_carried_as_an_unresolved_uncertainty():
    """It is settled: a record was reached. Only the two failures are uncertainties."""
    from src.core.uncertainty import uncertain_identifiers

    package = BUILDER.build(
        ContextOperation.ANALYZE, rule=RULE, retrieval=result(redirected(), unresolved())
    )
    assert [entry.identifier for entry in uncertain_identifiers(package)] == ["T9999"]
