"""Context exceptions.

Every failure leaving this package is one of these types.

An unresolved reference is not a failure — carrying it faithfully is the point.
These exceptions cover a package that cannot be built, one that would exceed its
budget under a policy that forbids reduction, and one that failed the checks
guarding what may leave this layer.
"""

from __future__ import annotations

from collections.abc import Sequence


class ContextError(Exception):
    """Base class for every context construction failure."""


class ContextBuildError(ContextError):
    """A context package could not be assembled from the inputs given."""

    def __init__(self, reason: str) -> None:
        """Record why construction stopped."""
        super().__init__(f"Context build failed: {reason}")
        self.reason = reason


class ContextBudgetExceededError(ContextError):
    """Content exceeds the budget and the policy forbids reducing it."""

    def __init__(self, used: int, allowed: int, policy: str) -> None:
        """Record the overrun and the policy that refused to reduce it."""
        super().__init__(
            f"Context needs {used} characters but only {allowed} are allowed "
            f"under truncation policy {policy!r}"
        )
        self.used = used
        self.allowed = allowed
        self.policy = policy


class ContextValidationError(ContextError):
    """A built package failed one or more consistency checks."""

    def __init__(self, messages: Sequence[str]) -> None:
        """Record every validation message."""
        super().__init__("Context validation failed: " + "; ".join(messages))
        self.messages = tuple(messages)


class SecretLeakError(ContextError):
    """A value that must never enter the context was supplied.

    Raised rather than redacted when the *object* is a credential holder, since
    accepting it at all would mean the caller believes secrets belong here.
    """

    def __init__(self, location: str, detail: str) -> None:
        """Record where the offending value appeared."""
        super().__init__(f"Refusing to place a secret into context at {location}: {detail}")
        self.location = location
        self.detail = detail
