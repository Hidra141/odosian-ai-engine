"""Knowledge exceptions.

Every failure leaving this package is one of these types.

A reference that does not resolve is *not* a failure. It is reported as a
result carrying :attr:`ResolutionStatus.UNRESOLVED`, because a corpus that does
not contain a target is a fact about the corpus rather than an error. These
exceptions cover a dataset that cannot be read and a record that cannot be
understood — cases where continuing would mean discarding data silently.
"""

from __future__ import annotations

from pathlib import Path


class KnowledgeError(Exception):
    """Base class for every knowledge layer failure."""


class UnknownKnowledgeSourceError(KnowledgeError):
    """A name does not denote one of the approved sources."""

    def __init__(self, value: object) -> None:
        """Record the unrecognised source name."""
        super().__init__(f"Unknown knowledge source: {value!r}")
        self.value = value


class KnowledgeSourceUnavailableError(KnowledgeError):
    """A source's dataset file is missing or unreadable."""

    def __init__(self, source: str, path: Path, reason: str) -> None:
        """Record the source, the path tried and why it failed."""
        super().__init__(f"Dataset for {source!r} is unavailable at {path}: {reason}")
        self.source = source
        self.path = path
        self.reason = reason


class RecordDecodeError(KnowledgeError):
    """A line is not decodable JSON.

    The record is never skipped. Reading stops so the corpus cannot be used
    while part of it is silently missing.
    """

    def __init__(self, source: str, path: Path, line_number: int, reason: str) -> None:
        """Record where decoding failed."""
        super().__init__(f"{source}: line {line_number} of {path} is not valid JSON: {reason}")
        self.source = source
        self.path = path
        self.line_number = line_number
        self.reason = reason


class InvalidRecordError(KnowledgeError):
    """A decoded line is not a record with the expected envelope."""

    def __init__(self, source: str, path: Path, line_number: int, reason: str) -> None:
        """Record which line failed the envelope check and why."""
        super().__init__(f"{source}: line {line_number} of {path} is not a valid record: {reason}")
        self.source = source
        self.path = path
        self.line_number = line_number
        self.reason = reason
