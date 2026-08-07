"""Prompt building.

Composes the final prompt for one operation:

    shared templates + system template  ->  system part
    instruction template                ->  instruction part

Each template is located, validated and rendered, then the parts are assembled
into a :class:`RenderedPrompt`. The result is a plain value object: this package
never sends it anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .prompt_models import (
    PromptRef,
    PromptRequest,
    RenderedPrompt,
    RenderedSegment,
)
from .prompt_renderer import PromptRenderer
from .prompt_repository import PromptRepository
from .prompt_validator import PromptValidator
from .types import (
    DEFAULT_INSTRUCTION_NAME,
    DEFAULT_SYSTEM_NAME,
    SEGMENT_SEPARATOR,
    PromptScope,
    PromptSegment,
    VariableMapping,
)


@dataclass(frozen=True, slots=True)
class PromptBuilder:
    """Assemble a ready-to-send prompt from the templates of one operation."""

    repository: PromptRepository
    renderer: PromptRenderer = field(default_factory=PromptRenderer)
    validator: PromptValidator = field(default_factory=PromptValidator)

    def build(self, request: PromptRequest) -> RenderedPrompt:
        """Load, validate, render and assemble the prompt for a request."""
        scope = PromptScope.for_operation(request.operation)
        variables = request.context.variables

        system_refs = (
            *request.shared_refs,
            request.system_ref or PromptRef(scope, DEFAULT_SYSTEM_NAME),
        )
        instruction_ref = request.instruction_ref or PromptRef(scope, DEFAULT_INSTRUCTION_NAME)

        segments = [
            self._render(PromptSegment.SYSTEM, ref, variables) for ref in system_refs
        ]
        segments.append(self._render(PromptSegment.INSTRUCTION, instruction_ref, variables))

        system_text = SEGMENT_SEPARATOR.join(
            segment.text for segment in segments if segment.segment is PromptSegment.SYSTEM
        )
        instruction_text = segments[-1].text

        used: list[str] = []
        for segment in segments:
            for name in segment.variables:
                if name not in used:
                    used.append(name)

        return RenderedPrompt(
            operation=request.operation,
            system=system_text,
            instruction=instruction_text,
            segments=tuple(segments),
            variables=tuple(used),
            sources=tuple(segment.source for segment in segments),
        )

    def _render(
        self,
        segment: PromptSegment,
        ref: PromptRef,
        variables: VariableMapping,
    ) -> RenderedSegment:
        """Load, validate and render one template."""
        path = self.repository.resolve(ref)
        template = self.repository.loader.load(path)
        self.validator.validate(template, variables).raise_if_invalid()
        return RenderedSegment(
            segment=segment,
            ref=ref,
            source=path,
            text=self.renderer.render(template, variables),
            variables=template.placeholders,
        )
