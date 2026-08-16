"""Formatter exceptions.

Raised when a result cannot be rendered into its contract.

These report a *structural* fault, never a semantic one. Whether a claim is
supported, whether an identifier was supplied, whether uncertainty survived —
all of that was settled at the Stage-16 boundary, and this layer does not ask
again. What it does check is that the object in front of it can actually be
written into the shape the contract states: the right result type for the
operation, and numbers inside the ranges the contract fixes.

A formatter that quietly emitted a malformed document would put the fault
somewhere nobody looks. Failing here keeps it where it happened.
"""

from __future__ import annotations


class FormatterError(Exception):
    """Base class for every formatting failure."""


class OperationMismatchError(FormatterError):
    """The result type does not answer the operation being formatted."""

    def __init__(self, expected: str, actual: str) -> None:
        """Record which formatter was asked for which result."""
        super().__init__(f"cannot format {actual} as {expected}")
        self.expected = expected
        self.actual = actual


class ScoreOutOfRangeError(FormatterError):
    """A score outside 0..100 has no rating and no place in the contract.

    Refused rather than clamped, which is what every other layer here does with
    a value outside its range: Stage-15's schema rejects it at the parse
    boundary and Stage-16 reports ``structural.out_of_range``. Silently pulling
    140 down to 100 would invent a grade nobody assigned.
    """

    def __init__(self, score: int) -> None:
        """Record the offending score."""
        super().__init__(f"score {score} is outside 0..100 and cannot be rated")
        self.score = score
