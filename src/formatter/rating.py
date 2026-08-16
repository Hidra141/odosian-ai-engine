"""Detection quality rating.

The letter grade an analysis carries, derived from its score.

    A+  95-100      A   85-94      B   70-84
    C   50-69       D   30-49      F    0-29

This is Odosian's detection-quality rating. It says how good the rule is as a
detection; it is not a severity, not a risk score, and not a judgement of how
confident the analysis was.

The model never supplies it. It supplies a score, and the grade follows from
that score by this table alone, so the two can never disagree — a model free to
report both could return 45 and "A+", and nothing downstream could tell which
half to believe.
"""

from __future__ import annotations

from typing import Final

from .exceptions import ScoreOutOfRangeError

BANDS: Final[tuple[tuple[int, str], ...]] = (
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (50, "C"),
    (30, "D"),
    (0, "F"),
)
"""Each band's lower bound and its letter, highest first.

Written as lower bounds rather than ranges so the boundaries cannot drift apart:
a band ends exactly where the next one begins, and 94 cannot become an ``A``
because 95 is the only place ``A+`` starts.
"""

MINIMUM: Final[int] = 0
MAXIMUM: Final[int] = 100


def rating_from_score(score: int) -> str:
    """Return the letter grade for a score, or raise when the score is not one.

    A score outside 0..100 is refused rather than clamped. Every other layer
    here treats an out-of-range number as a fault — Stage-15's schema rejects
    it, Stage-16 reports it — and pulling 140 down to 100 would hand back a
    grade nobody assigned.
    """
    if not isinstance(score, int) or isinstance(score, bool):
        raise ScoreOutOfRangeError(score)
    if not MINIMUM <= score <= MAXIMUM:
        raise ScoreOutOfRangeError(score)
    for lower, letter in BANDS:
        if score >= lower:
            return letter
    raise ScoreOutOfRangeError(score)  # unreachable: the last band starts at 0
