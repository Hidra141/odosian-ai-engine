"""The engine request.

What a caller asks for, before any stage has run.

Every request type the lower layers define already begins at a built context
package: Stage-15's :class:`~src.core.models.AnalyzeRequest` and its siblings
take one as their first field. That is the right shape for the reasoning layer
and the wrong shape for a caller, who holds a rule and a question rather than an
evidence package. This is the missing half — the input the pipeline accepts and
turns into the other.

Validation rejects; it never fills a gap in. A request naming an operation
without the material that operation needs is refused, and so is one carrying
material the operation has no field for. Silently discarding what a caller
supplied is the same fault as silently inventing what they did not, and a
generate request carrying a rule id is exactly that: the generate contract has
no ``ruleId``, so the value could only be dropped.

The refusal is Stage-15's :class:`~src.core.exceptions.InvalidReasoningRequestError`
rather than a new type. The fault it reports is the same one — a request that
cannot be executed as stated — and a second name for it would only make callers
catch two things where one will do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, final

from src.core.exceptions import InvalidReasoningRequestError
from src.core.types import ReasoningOperation

RULE_OPERATIONS: Final[frozenset[ReasoningOperation]] = frozenset(
    {ReasoningOperation.ANALYZE, ReasoningOperation.ENHANCE}
)
"""The operations that reason about a rule the caller already has.

Generate is the exception: it is asked about a requirement no rule yet
satisfies, which is why it takes different material and refuses a rule.
"""


@final
@dataclass(frozen=True, slots=True)
class EngineRequest:
    """One request to run an operation from raw input to a contract document."""

    operation: ReasoningOperation
    user_id: str
    rule_text: str = ""
    requirement: str = ""
    rule_id: str | None = None

    @property
    def is_rule_operation(self) -> bool:
        """Return whether this operation reasons about a supplied rule."""
        return self.operation in RULE_OPERATIONS

    def validate(self) -> None:
        """Raise when the request cannot be executed as stated."""
        if not self.user_id.strip():
            raise InvalidReasoningRequestError(
                f"operation {self.operation.value!r} needs a user id, and the request "
                "supplies none"
            )
        if self.is_rule_operation:
            self._validate_rule_operation()
        else:
            self._validate_requirement_operation()

    def _validate_rule_operation(self) -> None:
        """Raise when an analyze or enhance request is not usable."""
        name = self.operation.value
        if not self.rule_text.strip():
            raise InvalidReasoningRequestError(
                f"operation {name!r} needs a rule, and the request supplies none"
            )
        if self.requirement.strip():
            raise InvalidReasoningRequestError(
                f"operation {name!r} reasons about a rule rather than a requirement, and the "
                "request supplies a requirement that could only be discarded"
            )

    def _validate_requirement_operation(self) -> None:
        """Raise when a generate request is not usable."""
        name = self.operation.value
        if not self.requirement.strip():
            raise InvalidReasoningRequestError(
                f"operation {name!r} needs a detection requirement, and the request supplies none"
            )
        if self.rule_text.strip():
            raise InvalidReasoningRequestError(
                f"operation {name!r} writes a rule rather than reading one, and the request "
                "supplies a rule that could only be discarded"
            )
        if self.rule_id is not None:
            raise InvalidReasoningRequestError(
                f"operation {name!r} writes a rule that does not exist yet and its contract "
                "carries no rule id, so the supplied rule id could only be discarded"
            )
