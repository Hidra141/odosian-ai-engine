"""Unit tests for the retrieval metrics.

Pure functions over ranked lists, so these need no corpus, no index and no
retrieval. They pin the edge cases that silently corrupt an evaluation: empty
results, no relevant records, duplicates in a ranking, and graded gain.
"""

from __future__ import annotations

from src.evaluation.metrics import (
    dcg_at_k,
    dedupe,
    ideal_dcg_at_k,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)

RELEVANT = frozenset({"a", "b", "c"})
GRADES = {"a": 3, "b": 2, "c": 1}


def test_dedupe_keeps_first_occurrence() -> None:
    assert dedupe(["a", "b", "a", "c", "b"]) == ("a", "b", "c")


def test_precision_counts_only_relevant() -> None:
    assert precision_at_k(["a", "x", "b"], RELEVANT, 3) == 2 / 3


def test_precision_divides_by_k_not_by_results_returned() -> None:
    # A run returning one correct result must not score 1.0 at k=5.
    assert precision_at_k(["a"], RELEVANT, 5) == 1 / 5


def test_precision_of_empty_ranking_is_zero() -> None:
    assert precision_at_k([], RELEVANT, 5) == 0.0


def test_precision_with_no_relevant_records_is_zero() -> None:
    assert precision_at_k(["x", "y"], frozenset(), 2) == 0.0


def test_precision_with_all_relevant_is_one() -> None:
    assert precision_at_k(["a", "b", "c"], RELEVANT, 3) == 1.0


def test_precision_ignores_duplicate_hits() -> None:
    # "a" twice is one answer found, not two.
    assert precision_at_k(["a", "a", "x"], RELEVANT, 3) == 1 / 3


def test_recall_is_share_of_relevant_found() -> None:
    assert recall_at_k(["a", "b", "z"], RELEVANT, 3) == 2 / 3


def test_recall_with_empty_relevant_set_is_zero() -> None:
    assert recall_at_k(["a"], frozenset(), 5) == 0.0


def test_recall_is_bounded_by_k() -> None:
    assert recall_at_k(["a", "b", "c"], RELEVANT, 1) == 1 / 3


def test_reciprocal_rank_uses_first_relevant() -> None:
    assert reciprocal_rank(["x", "y", "b"], RELEVANT) == 1 / 3


def test_reciprocal_rank_is_one_when_first_is_relevant() -> None:
    assert reciprocal_rank(["a", "x"], RELEVANT) == 1.0


def test_reciprocal_rank_is_zero_when_nothing_relevant() -> None:
    assert reciprocal_rank(["x", "y"], RELEVANT) == 0.0


def test_reciprocal_rank_of_empty_ranking_is_zero() -> None:
    assert reciprocal_rank([], RELEVANT) == 0.0


def test_dcg_uses_graded_gain() -> None:
    # 2**3 - 1 = 7 at rank 1, undiscounted.
    assert dcg_at_k(["a"], GRADES, 1) == 7.0


def test_dcg_discounts_later_positions() -> None:
    first = dcg_at_k(["a", "b"], GRADES, 2)
    swapped = dcg_at_k(["b", "a"], GRADES, 2)
    assert first > swapped


def test_ideal_dcg_orders_grades_descending() -> None:
    assert ideal_dcg_at_k(GRADES, 3) == dcg_at_k(["a", "b", "c"], GRADES, 3)


def test_ndcg_is_one_for_perfect_order() -> None:
    assert ndcg_at_k(["a", "b", "c"], GRADES, 3) == 1.0


def test_ndcg_is_below_one_for_wrong_order() -> None:
    assert ndcg_at_k(["c", "b", "a"], GRADES, 3) < 1.0


def test_ndcg_is_zero_without_relevant_records() -> None:
    # Perfect and useless retrieval are indistinguishable here; do not report 1.0.
    assert ndcg_at_k(["x"], {}, 5) == 0.0


def test_ndcg_of_empty_ranking_is_zero() -> None:
    assert ndcg_at_k([], GRADES, 5) == 0.0


def test_ndcg_ignores_irrelevant_padding() -> None:
    assert ndcg_at_k(["a", "b", "c"], GRADES, 3) == ndcg_at_k(["a", "b", "c", "x"], GRADES, 3)


def test_zero_k_returns_zero_everywhere() -> None:
    assert precision_at_k(["a"], RELEVANT, 0) == 0.0
    assert dcg_at_k(["a"], GRADES, 0) == 0.0
    assert ndcg_at_k(["a"], GRADES, 0) == 0.0


def test_metrics_are_deterministic() -> None:
    ranking = ["x", "a", "a", "b", "z", "c"]
    first = (
        precision_at_k(ranking, RELEVANT, 5),
        recall_at_k(ranking, RELEVANT, 5),
        reciprocal_rank(ranking, RELEVANT),
        ndcg_at_k(ranking, GRADES, 5),
    )
    for _ in range(5):
        assert (
            precision_at_k(ranking, RELEVANT, 5),
            recall_at_k(ranking, RELEVANT, 5),
            reciprocal_rank(ranking, RELEVANT),
            ndcg_at_k(ranking, GRADES, 5),
        ) == first
