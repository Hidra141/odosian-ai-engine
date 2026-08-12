"""Response layer.

The common response object every provider returns.

Model output is excluded from the dataclass ``repr`` because it may quote the
runtime context supplied in the prompt. :meth:`LLMResponse.log_fields` returns
the subset that is safe to log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType

from .types import FinishReason, ProviderMetadata


def _empty_metadata() -> ProviderMetadata:
    """Return an immutable, empty metadata mapping."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Token counts reported by the provider.

    ``thoughts_tokens`` counts tokens a reasoning model spent thinking before
    answering. It is optional and defaults to zero, because most providers
    report nothing of the kind — but where it is reported it matters, since on
    those models thinking is paid for out of the same output allowance as the
    answer, and an answer that never arrives is usually one that was crowded
    out. Zero therefore means "not reported", which is also the honest reading
    for a provider that does not think.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    thoughts_tokens: int = 0

    @classmethod
    def unknown(cls) -> TokenUsage:
        """Return a zeroed usage record for providers that report nothing."""
        return cls()

    @property
    def output_tokens(self) -> int:
        """Return every token charged against the output allowance."""
        return self.completion_tokens + self.thoughts_tokens


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """One completed generation, in provider-neutral form."""

    text: str = field(repr=False)
    provider: str
    model: str
    finish_reason: FinishReason
    usage: TokenUsage
    duration_seconds: float
    metadata: ProviderMetadata = field(default_factory=_empty_metadata, repr=False)

    @property
    def is_truncated(self) -> bool:
        """Return whether generation stopped because the token limit was reached."""
        return self.finish_reason is FinishReason.MAX_TOKENS

    def log_fields(self) -> ProviderMetadata:
        """Return the fields that may be logged.

        Deliberately excludes the response text and any provider metadata, so a
        caller cannot log prompt or context content by logging this mapping.
        """
        return MappingProxyType(
            {
                "provider": self.provider,
                "model": self.model,
                "duration_seconds": f"{self.duration_seconds:.3f}",
                "finish_reason": self.finish_reason.value,
                "prompt_tokens": str(self.usage.prompt_tokens),
                "completion_tokens": str(self.usage.completion_tokens),
                "thoughts_tokens": str(self.usage.thoughts_tokens),
                "total_tokens": str(self.usage.total_tokens),
            }
        )
