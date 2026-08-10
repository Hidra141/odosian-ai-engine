"""Retrieval metrics.

Precision@K, Recall@K, MRR and NDCG@K, in the standard library only.

Every function takes a ranked sequence of record ids and a mapping of graded
relevance, and returns a number. They hold no state, consult nothing, and are
independently testable — which is why they are here rather than inside the
runner.

Duplicate ids in a ranked list are collapsed before scoring, keeping the first
occurrence. A retriever that returns the same record twice has not found two
answers, and counting it twice would inflate precision.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def dedupe(ranked: Sequence[str]) -> tuple[str, ...]:
    """Return a ranked list with repeats removed, first occurrence winning."""
    seen: list[str] = []
    for item in ranked:
        if item not in seen:
            seen.append(item)
    return tuple(seen)


def precision_at_k(ranked: Sequence[str], relevant: frozenset[str], k: int) -> float:
    """Return the share of the top ``k`` positions holding a relevant record.

    The denominator is ``k``, not the number retrieved, so a run that returns
    fewer than ``k`` results is not rewarded for its brevity.
    """
    if k <= 0:
        return 0.0
    top = dedupe(ranked)[:k]
    return sum(1 for item in top if item in relevant) / k


def recall_at_k(ranked: Sequence[str], relevant: frozenset[str], k: int) -> float:
    """Return the share of relevant records found in the top ``k``."""
    if not relevant:
        return 0.0
    top = dedupe(ranked)[:k]
    return sum(1 for item in top if item in relevant) / len(relevant)


def reciprocal_rank(ranked: Sequence[str], relevant: frozenset[str]) -> float:
    """Return ``1 / rank`` of the first relevant record, or zero if none."""
    for position, item in enumerate(dedupe(ranked), start=1):
        if item in relevant:
            return 1.0 / position
    return 0.0


def dcg_at_k(ranked: Sequence[str], grades: Mapping[str, int], k: int) -> float:
    """Return the discounted cumulative gain of the top ``k``.

    Uses the exponential gain ``2**grade - 1``, which separates a highly
    relevant record from a merely relevant one more sharply than a linear gain —
    appropriate here, where grade 3 means "this record *is* the answer".
    """
    if k <= 0:
        return 0.0
    total = 0.0
    for position, item in enumerate(dedupe(ranked)[:k], start=1):
        grade = grades.get(item, 0)
        if grade > 0:
            total += (2**grade - 1) / _log2(position + 1)
    return total


def ideal_dcg_at_k(grades: Mapping[str, int], k: int) -> float:
    """Return the best achievable gain for the top ``k``."""
    if k <= 0:
        return 0.0
    best = sorted((grade for grade in grades.values() if grade > 0), reverse=True)[:k]
    return sum((2**grade - 1) / _log2(position + 1) for position, grade in enumerate(best, start=1))


def ndcg_at_k(ranked: Sequence[str], grades: Mapping[str, int], k: int) -> float:
    """Return the normalised discounted cumulative gain of the top ``k``.

    Zero when nothing relevant exists, since perfect and useless retrieval are
    indistinguishable in that case and reporting 1.0 would flatter the system.
    """
    ideal = ideal_dcg_at_k(grades, k)
    if ideal <= 0.0:
        return 0.0
    return dcg_at_k(ranked, grades, k) / ideal


def _log2(value: int) -> float:
    """Return the base-2 logarithm of a positive integer."""
    import math

    return math.log2(value)
