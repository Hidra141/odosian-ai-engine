"""Provider interface.

The contract every provider adapter satisfies. It is a :class:`Protocol`, so an
adapter conforms by shape rather than by inheritance and can be written without
importing anything from this module.

The rest of the engine depends on this interface and never on a provider SDK.
Adding a provider means adding one class that satisfies it; no other module
changes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .request import LLMRequest
from .response import LLMResponse


@runtime_checkable
class LLMProvider(Protocol):
    """Executes a prepared request against one language model backend."""

    @property
    def name(self) -> str:
        """Return the provider's identifier, matching ``model.provider`` in config."""
        ...

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Execute one request and return the response.

        Implementations must raise only exceptions from this package's
        hierarchy. A provider SDK exception must never escape.
        """
        ...
