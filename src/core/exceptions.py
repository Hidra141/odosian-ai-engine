"""Reasoning engine exceptions.

The failures this layer *introduces*. It does not restate the ones it inherits:
a provider that times out raises Stage-07's ``LLMTimeoutError``, a body that is
not JSON raises Stage-07's ``LLMInvalidJSONError``, and a template that cannot
render raises Stage-06's ``PromptError``. Wrapping those in a second hierarchy
would hide which layer actually failed and would give the retry executor a type
it cannot classify.

What is new here is everything about *reasoning*: a request that cannot be
executed, a response whose structure does not match the operation's schema, and
a response that is well formed but says something the supplied context does not
permit it to say.

Following the layers before it, no exception in this module carries prompt text,
context text or response text. They carry field paths, identifiers and reasons.
"""

from __future__ import annotations

from collections.abc import Sequence


class ReasoningError(Exception):
    """Base class for every reasoning engine failure."""


class InvalidReasoningRequestError(ReasoningError):
    """A request cannot be executed as stated.

    Raised before anything is rendered or sent: an operation that disagrees with
    its context package, a package that carries no rule, a generate request with
    no requirement.
    """

    def __init__(self, reason: str) -> None:
        """Record why the request was refused."""
        super().__init__(f"Invalid reasoning request: {reason}")
        self.reason = reason


class PromptRenderingError(ReasoningError):
    """The prompt for a request could not be produced.

    Raised only from the boundary where Stage-06 is called, and always chained
    to the prompt error that caused it, so the underlying template fault stays
    reachable through ``__cause__``.
    """

    def __init__(self, operation: str, reason: str) -> None:
        """Record the operation whose prompt failed, and why."""
        super().__init__(f"Prompt rendering failed for operation {operation!r}: {reason}")
        self.operation = operation
        self.reason = reason


class ResponseSchemaError(ReasoningError):
    """A response does not match the schema of the operation it answers.

    Structural only: a missing field, a wrong type, a value outside an
    enumeration, a number outside its range, a field the schema does not define.
    Every issue found is reported, never only the first.
    """

    def __init__(self, operation: str, issues: Sequence[str]) -> None:
        """Record every structural issue found in the response."""
        super().__init__(
            f"Response schema validation failed for operation {operation!r}: "
            + "; ".join(issues)
        )
        self.operation = operation
        self.issues = tuple(issues)


class ReasoningValidationError(ReasoningError):
    """A well-formed response says something the supplied context does not permit.

    Raised for the checks that make the output trustworthy rather than merely
    parseable: an identifier the context reports unresolved presented as
    settled, an ambiguous identifier narrowed to one candidate, a citation of an
    item that was never supplied, an answer to a different operation.
    """

    def __init__(self, operation: str, issues: Sequence[str]) -> None:
        """Record every reasoning issue found in the response."""
        super().__init__(
            f"Reasoning validation failed for operation {operation!r}: " + "; ".join(issues)
        )
        self.operation = operation
        self.issues = tuple(issues)
