"""The runtime envelope's producer.

Stage-17 states that an analysis record carries fields no reasoning step can
produce — which request this was, who asked, when, and how long it took — and
refuses to invent them. This is the layer that owns them.

Three are produced here. ``id`` is fresh per run, ``created_at`` is the instant
the record was assembled, and ``latency_ms`` is measured around the whole
orchestration rather than around the provider call, because the caller waited
for all of it. The other two are copied from the request: ``user_id`` and
``rule_id`` belong to whoever asked, and neither is ever guessed.

Nothing here reaches Stage-15's :class:`~src.core.models.ReasoningProvenance`,
which deliberately omits a duration so that two identical runs compare equal.
The duration lives here instead, where varying between runs is the point.

The three sources of variation are injected. A test supplies its own clock,
identifier and timer and gets a byte-identical document; production takes the
defaults and gets a real one. This is the idiom Stage-07 already uses for its
``sleep``.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, final

from src.formatter.runtime import RuntimeContext

from .requests import EngineRequest

TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S"
"""The contract's timestamp, up to the seconds it states explicitly.

The milliseconds and the ``Z`` are appended by :func:`as_timestamp`. Python's
own ``isoformat`` writes microseconds and a ``+00:00`` offset, neither of which
is the shape the contract demonstrates.
"""

MILLISECONDS_PER_SECOND: Final[int] = 1000


def utc_now() -> datetime:
    """Return the current instant, in UTC."""
    return datetime.now(UTC)


def new_uuid() -> str:
    """Return a fresh random identifier."""
    return str(uuid.uuid4())


def as_timestamp(moment: datetime) -> str:
    """Render an instant as ``YYYY-MM-DDTHH:MM:SS.mmmZ``.

    The instant is converted to UTC first, so a caller's clock returning a local
    time cannot put a local wall reading behind a ``Z``.
    """
    utc = moment.astimezone(UTC)
    milliseconds = utc.microsecond // 1000
    return f"{utc.strftime(TIMESTAMP_FORMAT)}.{milliseconds:03d}Z"


@final
@dataclass(frozen=True, slots=True)
class RuntimeFactory:
    """Produces the runtime envelope Stage-17 requires, from injectable sources."""

    now: Callable[[], datetime] = utc_now
    new_id: Callable[[], str] = new_uuid
    timer: Callable[[], float] = time.perf_counter

    def start(self) -> float:
        """Return the reading a later :meth:`create` measures against."""
        return self.timer()

    def elapsed_ms(self, started: float) -> int:
        """Return whole milliseconds since a reading from :meth:`start`.

        Never negative. A clock that steps backwards is a broken clock, and a
        negative duration in a record would be read as a broken engine.
        """
        elapsed = (self.timer() - started) * MILLISECONDS_PER_SECOND
        return max(round(elapsed), 0)

    def create(
        self,
        request: EngineRequest,
        *,
        started: float,
        input_query: str,
    ) -> RuntimeContext:
        """Return the envelope for one completed run."""
        return RuntimeContext(
            id=self.new_id(),
            user_id=request.user_id,
            created_at=as_timestamp(self.now()),
            latency_ms=self.elapsed_ms(started),
            rule_id=request.rule_id,
            input_query=input_query,
        )
