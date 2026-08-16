"""The runtime envelope.

The values the application owns and the engine does not.

Every contract carries fields no reasoning step can produce: which request this
was, who asked, when, and how long it took. The engine does not know them, and
two of them it must not know — a timestamp and a duration vary between
otherwise identical runs, which is exactly why
:class:`~src.core.models.ReasoningProvenance` leaves the duration out.

So they arrive here instead, supplied by the caller. Nothing in this package
generates one. The required fields have no defaults, which makes a caller that
forgot one fail at construction rather than ship a plausible blank.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import final


@final
@dataclass(frozen=True, slots=True)
class RuntimeContext:
    """What the application knows about a request that the engine does not."""

    id: str
    """This analysis record's own identifier."""

    user_id: str
    """The account the request was made under."""

    created_at: str
    """When the record was generated, ISO 8601, as the application recorded it."""

    latency_ms: int
    """How long the call took, measured by the caller."""

    rule_id: str | None = None
    """The saved rule this concerns, or ``None`` for an ad-hoc query.

    ``None`` rather than an empty string, because the contract demonstrates a
    JSON ``null`` here for the ad-hoc case.
    """

    input_query: str = ""
    """The query the caller submitted.

    Used where the result cannot supply it. An enhancement reports the original
    query on the result itself, so that formatter reads it there instead.
    """

    saved_rule_id: str | None = None
    """The rule a generation was saved as, when it was saved."""

    saved_rule_title: str | None = None
    """That rule's title, when it was saved."""

    @property
    def saved(self) -> bool:
        """Return whether a generated rule was persisted.

        Both halves are required. The contract emits the pair only when the
        request asked for a save, so a half-filled pair is treated as no save
        rather than as a document with one field missing.
        """
        return self.saved_rule_id is not None and self.saved_rule_title is not None
