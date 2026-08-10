"""Request layer.

Converts a fully rendered prompt plus configured model settings into a
provider-neutral request object.

This is the only module in the package that knows the prompt package exists.
Everything downstream of it works on :class:`LLMRequest`, so a provider adapter
never sees a prompt type.

Prompt text is excluded from the dataclass ``repr``. A request object can be
logged or included in a traceback without leaking the prompt or the runtime
context it carries.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.config.settings import ModelSettings
from src.prompts.prompt_models import RenderedPrompt

from .types import ResponseFormat


@dataclass(frozen=True, slots=True)
class GenerationParameters:
    """Runtime parameters for one generation call.

    Every value originates in the configuration system. Nothing here carries a
    default, so a missing setting fails at construction rather than silently
    substituting a hidden value.
    """

    model: str
    temperature: float
    top_p: float
    max_output_tokens: int
    timeout_seconds: int

    @classmethod
    def from_settings(cls, settings: ModelSettings) -> GenerationParameters:
        """Build generation parameters from the configured model settings."""
        return cls(
            model=settings.name,
            temperature=settings.temperature,
            top_p=settings.top_p,
            max_output_tokens=settings.max_output_tokens,
            timeout_seconds=settings.timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """A provider-neutral request ready for execution."""

    system: str = field(repr=False)
    instruction: str = field(repr=False)
    parameters: GenerationParameters
    response_format: ResponseFormat = ResponseFormat.JSON
    operation: str = ""

    @classmethod
    def from_rendered_prompt(
        cls,
        prompt: RenderedPrompt,
        settings: ModelSettings,
        *,
        response_format: ResponseFormat = ResponseFormat.JSON,
    ) -> LLMRequest:
        """Build a request from an already rendered prompt.

        The prompt is taken as final. This layer performs no substitution, no
        validation and no assembly of its own.
        """
        return cls(
            system=prompt.system,
            instruction=prompt.instruction,
            parameters=GenerationParameters.from_settings(settings),
            response_format=response_format,
            operation=prompt.operation.value,
        )

    @property
    def has_system(self) -> bool:
        """Return whether a system part was supplied."""
        return bool(self.system.strip())
