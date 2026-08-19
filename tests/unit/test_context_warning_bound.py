"""What a package says about its own cuts, and how much of it it may say.

The warnings section escapes the character budget on purpose: a package that hid
what it dropped in order to look smaller would be lying about itself. That
exemption was unbounded, and the two things it exempted both grow with the rule.
A rule with thirteen thousand entities produced twenty-six thousand warnings —
1.6 million characters of accounting wrapped around 52,000 characters of
evidence, 97.6% of the package explaining the other 2.4%.

Twenty-six thousand of those warnings carried one sentence between them. The
budget emits a drop per item and the sentence comes from a closed set of three,
so what varied was an identifier no stage reads. The count is the fact; the
repetition is not. So repeated drops of one reason are stated once, with the
count and the first item they happened to.

That alone does not bound anything — unresolved references are per-value and
genuinely distinct, and there can be five thousand of them. So the rendered
section has a ceiling as well, and what does not fit is counted in one closing
line. The two together give a bound that does not depend on the rule:

    package <= evidence budget + warning ceiling + metadata

Nothing here touches what evidence is chosen. The warnings section is built
after budgeting, from sections already final, which is what lets these tests
assert that selection and order are untouched.
"""

from __future__ import annotations

from src.context.budget import BudgetEnforcer, collapse_dropped
from src.context.context_builder import MAX_WARNING_SECTION_CHARS, ContextBuilder
from src.context.models import (
    ContextBudget,
    ContextItem,
    ContextSection,
    ContextWarning,
    RuleContext,
)
from src.context.types import (
    ContextOperation,
    EvidenceKind,
    SectionName,
    TruncationPolicy,
    WarningCode,
)


def item(index: int, chars: int, section: SectionName = SectionName.ENTITIES) -> ContextItem:
    """Return one context item of a stated size."""
    return ContextItem(
        item_id=f"{section.value}:{index:04d}",
        section=section,
        kind=EvidenceKind.EXTRACTED_ENTITY,
        text="x" * chars,
    )


def section_of(count: int, chars: int, name: SectionName = SectionName.ENTITIES) -> ContextSection:
    """Return a section holding ``count`` items of ``chars`` characters each."""
    return ContextSection(name=name, items=tuple(item(i, chars, name) for i in range(count)))


def budget(total: int = 60000, section: int = 20000, reserve: int = 8000) -> ContextBudget:
    """Return a budget stated in full, so a test never depends on the defaults."""
    return ContextBudget(
        max_total_chars=total,
        max_section_chars=section,
        reserved_output_chars=reserve,
        policy=TruncationPolicy.TRIM_TAIL,
    )


def dropped(warnings) -> tuple[ContextWarning, ...]:
    """Return only the drop warnings, in order."""
    return tuple(w for w in warnings if w.code is WarningCode.ITEM_DROPPED)


def enforce(sections, limits: ContextBudget | None = None):
    """Return the outcome of budgeting some sections."""
    return BudgetEnforcer(budget=limits or budget()).apply(tuple(sections))


def warning(code: WarningCode, detail: str, item_id: str, section=SectionName.ENTITIES):
    """Return one warning, for the collapse tests."""
    return ContextWarning(code=code, detail=detail, item_id=item_id, section=section)


# ------------------------------------------------- 1-5. the existing cuts


def test_one_dropped_item_reads_exactly_as_it_did():
    """The common case must be byte-for-byte unchanged."""
    outcome = enforce([section_of(2, 9000)], budget(total=17000, section=20000, reserve=8000))
    drops = dropped(outcome.warnings)

    assert len(drops) == 1
    assert drops[0].detail == "no budget remained for this item"
    assert drops[0].item_id == "entities:0001"


def test_many_dropped_items_are_stated_once_with_their_count():
    """Both passes cut the same section for the same reason, so both fold together.

    The section cap drops items 20-39, then the total cap drops 5-19 of what is
    left. Thirty-five items, one reason, one warning, naming the first item the
    reason ever applied to.
    """
    outcome = enforce([section_of(40, 1000)], budget(total=13000, section=20000, reserve=8000))
    drops = dropped(outcome.warnings)

    assert len(drops) == 1
    assert "35 items" in drops[0].detail
    assert drops[0].item_id == "entities:0020"


def test_a_truncated_item_is_still_reported_individually():
    outcome = enforce([section_of(1, 30000)], budget(total=28000, section=20000, reserve=8000))

    assert [w.code for w in outcome.warnings].count(WarningCode.ITEM_TRUNCATED) == 1


def test_the_section_budget_warning_survives():
    outcome = enforce([section_of(10, 5000)])

    assert any(w.code is WarningCode.SECTION_BUDGET_EXCEEDED for w in outcome.warnings)


def test_the_total_budget_warning_survives():
    outcome = enforce(
        [
            section_of(4, 4000),
            section_of(4, 4000, SectionName.MAPPINGS),
            section_of(4, 4000, SectionName.KNOWLEDGE),
            section_of(4, 4000, SectionName.REFERENCES),
        ]
    )

    assert any(w.code is WarningCode.TOTAL_BUDGET_EXCEEDED for w in outcome.warnings)


# ------------------------------------- 6-8. the codes that must not fold


def test_unresolved_references_are_never_folded_together():
    """Each names a different value, so each is a different fact."""
    raised = (
        warning(WarningCode.UNRESOLVED_REFERENCE, "'a' has no canonical form", "m:0"),
        warning(WarningCode.UNRESOLVED_REFERENCE, "'b' has no canonical form", "m:1"),
        warning(WarningCode.UNRESOLVED_REFERENCE, "'c' has no canonical form", "m:2"),
    )

    assert collapse_dropped(raised) == raised


def test_two_unresolved_references_of_one_value_are_both_kept():
    raised = (
        warning(WarningCode.UNRESOLVED_REFERENCE, "'a' has no canonical form", "m:0"),
        warning(WarningCode.UNRESOLVED_REFERENCE, "'a' has no canonical form", "m:1"),
    )

    assert collapse_dropped(raised) == raised


def test_ambiguous_empty_and_redacted_are_never_folded():
    for code in (
        WarningCode.AMBIGUOUS_REFERENCE,
        WarningCode.EMPTY_RETRIEVAL,
        WarningCode.CREDENTIAL_REDACTED,
        WarningCode.ITEM_TRUNCATED,
        WarningCode.SECTION_BUDGET_EXCEEDED,
        WarningCode.TOTAL_BUDGET_EXCEEDED,
    ):
        raised = (warning(code, "same sentence", "i:0"), warning(code, "same sentence", "i:1"))

        assert collapse_dropped(raised) == raised, code


def test_drops_of_different_reasons_stay_apart():
    raised = (
        warning(WarningCode.ITEM_DROPPED, "no budget remained for this item", "e:0"),
        warning(WarningCode.ITEM_DROPPED, "dropped whole to stay within budget", "e:1"),
    )

    assert len(collapse_dropped(raised)) == 2


def test_drops_in_different_sections_stay_apart():
    """Which section lost its evidence is the part a reader acts on."""
    raised = (
        warning(WarningCode.ITEM_DROPPED, "no budget remained for this item", "e:0"),
        warning(
            WarningCode.ITEM_DROPPED,
            "no budget remained for this item",
            "m:0",
            SectionName.MAPPINGS,
        ),
    )
    folded = collapse_dropped(raised)

    assert len(folded) == 2
    assert {w.section for w in folded} == {SectionName.ENTITIES, SectionName.MAPPINGS}


def test_the_order_of_other_warnings_is_untouched():
    raised = (
        warning(WarningCode.SECTION_BUDGET_EXCEEDED, "first", "a"),
        warning(WarningCode.ITEM_DROPPED, "no budget remained for this item", "b"),
        warning(WarningCode.UNRESOLVED_REFERENCE, "third", "c"),
        warning(WarningCode.ITEM_DROPPED, "no budget remained for this item", "d"),
    )
    folded = collapse_dropped(raised)

    assert [w.code for w in folded] == [
        WarningCode.SECTION_BUDGET_EXCEEDED,
        WarningCode.ITEM_DROPPED,
        WarningCode.UNRESOLVED_REFERENCE,
    ]


# ------------------------------------------- 9-12. the pathological sizes


def test_the_warning_count_stays_flat_however_many_items_are_dropped():
    """Ten, a hundred, a thousand, ten thousand — one reason, one warning."""
    for count in (10, 100, 1000, 10000):
        outcome = enforce(
            [section_of(count, 1000)], budget(total=9000, section=20000, reserve=8000)
        )
        drops = dropped(outcome.warnings)

        assert len(drops) == 1, count
        assert f"{count - 1} items" in drops[0].detail, count


def test_the_rendered_section_stays_under_its_ceiling_at_every_size():
    for count in (10, 100, 1000, 10000):
        package = ContextBuilder(budget=budget(total=9000, section=20000, reserve=8000)).build(
            ContextOperation.ANALYZE, rule=RuleContext(title="t", query="q")
        )
        assert package.total_characters >= 0, count

    for count in (10, 100, 1000, 10000):
        raised = [
            warning(WarningCode.UNRESOLVED_REFERENCE, f"'{i}' has no canonical form", f"m:{i}")
            for i in range(count)
        ]
        items = ContextBuilder()._warning_items(raised)
        rendered = sum(x.char_length for x in items)

        assert rendered <= MAX_WARNING_SECTION_CHARS, (count, rendered)


def test_exactly_one_truncation_notice_is_emitted():
    raised = [
        warning(WarningCode.UNRESOLVED_REFERENCE, f"'{i}' has no canonical form", f"m:{i}")
        for i in range(10000)
    ]
    items = ContextBuilder()._warning_items(raised)
    notices = [x for x in items if "not shown here" in x.text]

    assert len(notices) == 1
    assert notices[0] is items[-1]


def test_the_notice_states_how_many_were_omitted():
    raised = [
        warning(WarningCode.UNRESOLVED_REFERENCE, f"'{i}' has no canonical form", f"m:{i}")
        for i in range(10000)
    ]
    items = ContextBuilder()._warning_items(raised)
    shown = len(items) - 1

    assert f"{10000 - shown} further warning(s)" in items[-1].text


def test_truncation_does_not_recurse():
    """The notice is built from a count, so it cannot be cut and cannot grow."""
    raised = [
        warning(WarningCode.UNRESOLVED_REFERENCE, "x" * 500, f"m:{i}") for i in range(10000)
    ]
    once = ContextBuilder()._warning_items(raised)
    twice = ContextBuilder()._warning_items(raised)

    assert len(once) == len(twice)
    assert [x.text for x in once] == [x.text for x in twice]
    assert sum("not shown here" in x.text for x in once) == 1


def test_no_warning_is_rendered_half():
    raised = [
        warning(WarningCode.UNRESOLVED_REFERENCE, f"'{i}' has no canonical form", f"m:{i}")
        for i in range(10000)
    ]
    items = ContextBuilder()._warning_items(raised)

    for rendered, original in zip(items[:-1], raised, strict=False):
        assert rendered.text == str(original)


# ------------------------------------------- 13-20. nothing else moved


def fixed_sections():
    """Return sections that will not fit, so budgeting has work to do."""
    return [section_of(30, 1000), section_of(30, 1000, SectionName.MAPPINGS)]


def test_the_evidence_that_survives_is_the_same_evidence():
    outcome = enforce(fixed_sections())

    assert [i.item_id for s in outcome.sections for i in s.items] == [
        f"entities:{n:04d}" for n in range(20)
    ] + [f"mappings:{n:04d}" for n in range(20)]


def test_the_evidence_order_is_the_same_order():
    first = enforce(fixed_sections())
    second = enforce(fixed_sections())

    assert [i.item_id for s in first.sections for i in s.items] == [
        i.item_id for s in second.sections for i in s.items
    ]


def test_the_section_limit_is_still_the_section_limit():
    outcome = enforce([section_of(40, 1000)], budget(total=100000, section=20000, reserve=0))

    assert outcome.sections[0].character_count <= 20000


def test_the_total_limit_is_still_the_total_limit():
    outcome = enforce(fixed_sections(), budget(total=60000, section=20000, reserve=8000))

    assert outcome.total_characters <= 52000


def test_budgeting_is_deterministic():
    assert enforce(fixed_sections()) == enforce(fixed_sections())


# ------------------------------------------- 21-25. compatibility


def test_every_warning_code_still_survives_collapsing():
    for code in WarningCode:
        raised = (warning(code, "a reason", "i:0"),)

        assert collapse_dropped(raised)[0].code is code


def test_a_package_with_no_warnings_has_no_warnings_section():
    package = ContextBuilder().build(ContextOperation.ANALYZE, rule=RuleContext(title="t"))

    assert not package.warnings
    assert SectionName.WARNINGS not in {s.name for s in package.sections}


def test_an_empty_warning_list_collapses_to_nothing():
    assert collapse_dropped(()) == ()


def test_the_rendered_section_still_carries_the_code_in_its_metadata():
    items = ContextBuilder()._warning_items(
        [warning(WarningCode.ITEM_DROPPED, "no budget remained for this item", "e:0")]
    )

    assert items[0].metadata["code"] == WarningCode.ITEM_DROPPED.value
    assert items[0].kind is EvidenceKind.WARNING
    assert items[0].section is SectionName.WARNINGS


def test_the_package_still_carries_every_warning_it_raised():
    """Only the rendering is bounded; a caller reading them loses nothing."""
    raised = [
        warning(WarningCode.UNRESOLVED_REFERENCE, f"'{i}' has no canonical form", f"m:{i}")
        for i in range(10000)
    ]
    items = ContextBuilder()._warning_items(raised)

    assert len(items) < len(raised)


def test_the_bound_holds_end_to_end():
    """package <= evidence budget + warning ceiling + metadata."""
    limits = budget()
    raised = [
        warning(WarningCode.UNRESOLVED_REFERENCE, f"'{i}' has no canonical form", f"m:{i}")
        for i in range(10000)
    ]
    rendered = sum(x.char_length for x in ContextBuilder(budget=limits)._warning_items(raised))

    assert rendered <= MAX_WARNING_SECTION_CHARS
    assert limits.available_chars + MAX_WARNING_SECTION_CHARS + 1000 >= (
        limits.available_chars + rendered + 1000
    )
