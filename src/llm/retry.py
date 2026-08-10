"""Retry.

Re-runs an operation while it fails transiently.

Whether a failure is transient is decided by the exception type alone, through
:attr:`LLMError.transient`. A non-transient failure — bad credentials, an
unknown model, an unusable response — is raised on its first occurrence.

``time.sleep`` is injected rather than called directly, so the backoff schedule
can be exercised without waiting.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from src.config.settings import ModelSettings

from .exceptions import LLMError

_T = TypeVar("_T")

RetryObserver = Callable[[int, LLMError, float], None]


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How many attempts to make, and how long to wait between them."""

    max_attempts: int
    backoff_seconds: float

    @classmethod
    def from_settings(cls, settings: ModelSettings) -> RetryPolicy:
        """Build a policy from configuration.

        ``max_retries`` counts retries, so the attempt budget is one more than
        that: the initial call plus each configured retry.
        """
        return cls(
            max_attempts=settings.max_retries + 1,
            backoff_seconds=settings.retry_backoff_seconds,
        )

    def delay_for(self, attempt: int) -> float:
        """Return the delay before the attempt following ``attempt``.

        Exponential: the configured backoff doubles with each attempt made.
        """
        return self.backoff_seconds * float(2 ** (attempt - 1))


@dataclass(frozen=True, slots=True)
class RetryExecutor:
    """Runs an operation under a retry policy."""

    policy: RetryPolicy
    sleep: Callable[[float], None] = field(default=time.sleep)

    def call(self, operation: Callable[[], _T], observer: RetryObserver | None = None) -> _T:
        """Run ``operation``, retrying while it fails transiently.

        The observer, when given, is notified before each wait with the attempt
        number, the failure, and the delay about to be taken.
        """
        attempt = 0
        while True:
            attempt += 1
            try:
                return operation()
            except LLMError as error:
                if not error.transient or attempt >= self.policy.max_attempts:
                    raise
                delay = self.policy.delay_for(attempt)
                if observer is not None:
                    observer(attempt, error, delay)
                self.sleep(delay)
