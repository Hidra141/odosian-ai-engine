"""Knowledge graph exceptions.

Every failure leaving this package is one of these types.

A reference that cannot be resolved is not a failure. It is recorded in the
build diagnostics and produces no edge, because a corpus that does not contain a
target is a fact about the corpus. These exceptions cover a graph that is
internally inconsistent, or a backend that could not be reached.
"""

from __future__ import annotations

from collections.abc import Sequence


class GraphError(Exception):
    """Base class for every knowledge graph failure."""


class GraphBuildError(GraphError):
    """The graph could not be built from the corpus."""

    def __init__(self, reason: str) -> None:
        """Record why building stopped."""
        super().__init__(f"Graph build failed: {reason}")
        self.reason = reason


class GraphValidationError(GraphError):
    """The built graph failed one or more consistency checks."""

    def __init__(self, messages: Sequence[str]) -> None:
        """Record every validation message."""
        super().__init__("Graph validation failed: " + "; ".join(messages))
        self.messages = tuple(messages)


class GraphStoreError(GraphError):
    """A graph store could not complete an operation."""

    def __init__(self, store: str, reason: str) -> None:
        """Record which store failed and why."""
        super().__init__(f"Graph store {store!r} failed: {reason}")
        self.store = store
        self.reason = reason


class GraphBackendUnavailableError(GraphStoreError):
    """A backend driver is not installed or the server cannot be reached.

    Raised instead of degrading to a no-op, so an unavailable database is never
    mistaken for a successful write.
    """
