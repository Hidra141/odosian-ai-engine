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
from src.config.types import ThinkingLevel
from src.prompts.prompt_models import RenderedPrompt

from .types import JSONSchema, ResponseFormat


@dataclass(frozen=True, slots=True)
class GenerationParameters:
    """Runtime parameters for one generation call.

    Every value originates in the configuration system. Nothing here carries a
    default except ``thinking_level``, so a missing setting fails at
    construction rather than silently substituting a hidden value.

    ``thinking_level`` is the exception because unset is a meaningful state: it
    means the provider's own default reasoning behaviour applies, which is what
    every provider did before the setting existed.
    """

    model: str
    temperature: float
    top_p: float
    max_output_tokens: int
    timeout_seconds: int
    thinking_level: ThinkingLevel | None = None

    @classmethod
    def from_settings(cls, settings: ModelSettings) -> GenerationParameters:
        """Build generation parameters from the configured model settings."""
        return cls(
            model=settings.name,
            temperature=settings.temperature,
            top_p=settings.top_p,
            max_output_tokens=settings.max_output_tokens,
            timeout_seconds=settings.timeout_seconds,
            thinking_level=settings.thinking_level,
        )


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """A provider-neutral request ready for execution.

    ``response_json_schema`` states the shape the caller requires, in plain
    JSON Schema. A provider that can enforce a schema is asked to; one that
    cannot ignores it, and the caller's own validation still applies. The field
    is optional, so every request written before it existed still builds.
    """

    system: str = field(repr=False)
    instruction: str = field(repr=False)
    parameters: GenerationParameters
    response_format: ResponseFormat = ResponseFormat.JSON
    operation: str = ""
    response_json_schema: JSONSchema | None = field(default=None, repr=False)

    @classmethod
    def from_rendered_prompt(
        cls,
        prompt: RenderedPrompt,
        settings: ModelSettings,
        *,
        response_format: ResponseFormat = ResponseFormat.JSON,
        response_json_schema: JSONSchema | None = None,
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
            response_json_schema=response_json_schema,
        )

    @property
    def has_schema(self) -> bool:
        """Return whether the caller stated a required response shape."""
        return self.response_json_schema is not None

    @property
    def has_system(self) -> bool:
        """Return whether a system part was supplied."""
        return bool(self.system.strip())
