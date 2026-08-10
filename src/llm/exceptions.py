"""LLM layer exceptions.

Every failure leaving this package is one of these types. Provider SDK
exceptions are mapped at the adapter boundary and never propagate outward.

Each class declares whether it represents a transient condition. The retry
executor consults that flag and nothing else, so retry behaviour is a property
of the error type rather than a table kept somewhere separate.
"""

from __future__ import annotations

from typing import ClassVar


class LLMError(Exception):
    """Base class for every LLM layer failure."""

    transient: ClassVar[bool] = False


class LLMProviderError(LLMError):
    """A request to the provider failed for an unclassified reason."""

    transient: ClassVar[bool] = False

    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        model: str = "",
        status_code: int | None = None,
    ) -> None:
        """Record the failure together with the provider it came from."""
        super().__init__(message)
        self.provider = provider
        self.model = model
        self.status_code = status_code


class LLMAuthenticationError(LLMProviderError):
    """Credentials were rejected. Retrying cannot help."""

    transient: ClassVar[bool] = False


class LLMModelUnavailableError(LLMProviderError):
    """The requested model does not exist or is not accessible."""

    transient: ClassVar[bool] = False


class LLMRateLimitError(LLMProviderError):
    """The provider is rate limiting. Retrying after a delay may succeed."""

    transient: ClassVar[bool] = True


class LLMServiceUnavailableError(LLMProviderError):
    """The provider reported an internal failure. Retrying may succeed."""

    transient: ClassVar[bool] = True


class LLMConnectionError(LLMProviderError):
    """The provider could not be reached. Retrying may succeed."""

    transient: ClassVar[bool] = True


class LLMTimeoutError(LLMProviderError):
    """The request exceeded the configured timeout."""

    transient: ClassVar[bool] = True


class LLMInvalidResponseError(LLMError):
    """The provider replied, but the reply is not usable."""

    transient: ClassVar[bool] = False

    def __init__(self, message: str, *, provider: str = "", model: str = "") -> None:
        """Record the unusable reply together with its origin."""
        super().__init__(message)
        self.provider = provider
        self.model = model


class LLMInvalidJSONError(LLMInvalidResponseError):
    """The response body is not valid JSON.

    This layer reports the failure and stops. It never repairs the body.
    """

    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        model: str = "",
        position: int | None = None,
    ) -> None:
        """Record the decode failure and where in the body it occurred."""
        super().__init__(message, provider=provider, model=model)
        self.position = position
