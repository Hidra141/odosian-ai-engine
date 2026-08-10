"""Evaluation exceptions.

A case with no ground truth is not a failure — several security cases exist
precisely because the corpus defines nothing for their identifier. These
exceptions cover a benchmark that cannot be grounded and a run that would
disturb the corpus it measures.
"""

from __future__ import annotations

from pathlib import Path


class EvaluationError(Exception):
    """Base class for every evaluation failure."""


class BenchmarkGroundingError(EvaluationError):
    """A benchmark case names something the corpus does not contain."""

    def __init__(self, case_id: str, reason: str) -> None:
        """Record which case could not be grounded and why."""
        super().__init__(f"Case {case_id!r} cannot be grounded: {reason}")
        self.case_id = case_id
        self.reason = reason


class CorpusModifiedError(EvaluationError):
    """A dataset changed during an evaluation run."""

    def __init__(self, path: Path, before: str, after: str) -> None:
        """Record the dataset and the digests either side of the run."""
        super().__init__(f"{path} changed during evaluation: {before[:16]} -> {after[:16]}")
        self.path = path
        self.before = before
        self.after = after
