"""GraphRAG exceptions.

Every failure leaving this package is one of these types.

A query that matches nothing is not a failure: it returns an empty result with
its statistics intact. A reference that does not resolve is not a failure
either; it is reported as an unresolved seed. These exceptions cover a
retriever asked to work before it has an index, a query that cannot be honoured
as written, and derived data that would land somewhere it must not.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path


class GraphRagError(Exception):
    """Base class for every GraphRAG failure."""


class IndexNotBuiltError(GraphRagError):
    """Retrieval was attempted before the index was built."""

    def __init__(self, component: str) -> None:
        """Record which component has no index yet."""
        super().__init__(f"{component} has no index; call build_index() first")
        self.component = component


class InvalidRetrievalQueryError(GraphRagError):
    """A query cannot be honoured as written."""

    def __init__(self, reason: str) -> None:
        """Record why the query was rejected."""
        super().__init__(f"Invalid retrieval query: {reason}")
        self.reason = reason


class IndexPersistenceError(GraphRagError):
    """A derived index could not be written, or was aimed at protected data."""

    def __init__(self, path: Path, reason: str) -> None:
        """Record the target path and why the write was refused."""
        super().__init__(f"Cannot persist index at {path}: {reason}")
        self.path = path
        self.reason = reason


class RetrievalValidationError(GraphRagError):
    """A retrieval result failed its consistency checks."""

    def __init__(self, messages: Sequence[str]) -> None:
        """Record every validation message."""
        super().__init__("Retrieval validation failed: " + "; ".join(messages))
        self.messages = tuple(messages)
