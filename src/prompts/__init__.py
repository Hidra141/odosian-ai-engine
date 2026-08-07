"""Prompt management.

Loads prompt templates from the ``prompts/`` resource tree, validates them,
substitutes variables and assembles a ready-to-send prompt object.

This package never talks to a language model. It produces a
:class:`~src.prompts.prompt_models.RenderedPrompt` and stops there; sending it
is the responsibility of the LLM layer.

Typical use::

    repository = PromptRepository(root=prompts_dir)
    builder = PromptBuilder(repository=repository)
    prompt = builder.build(
        PromptRequest(
            operation=PromptOperation.ANALYZE,
            context=PromptContext.of(RULE=rule_text, CONTEXT=context_text),
        )
    )
"""

from __future__ import annotations

from .exceptions import (
    EmptyTemplateError,
    InvalidPromptReferenceError,
    InvalidTemplateError,
    MissingVariableError,
    PromptDecodeError,
    PromptError,
    PromptFileNotFoundError,
    PromptValidationError,
    UnknownPlaceholderError,
)
from .placeholders import (
    ANY_PLACEHOLDER_PATTERN,
    VALID_NAME_PATTERN,
    find_malformed,
    find_placeholders,
)
from .prompt_builder import PromptBuilder
from .prompt_loader import PromptLoader
from .prompt_models import (
    PromptContext,
    PromptMetadata,
    PromptRef,
    PromptRequest,
    PromptTemplate,
    RenderedPrompt,
    RenderedSegment,
)
from .prompt_renderer import PromptRenderer
from .prompt_repository import PromptRepository
from .prompt_validator import PromptIssue, PromptValidationResult, PromptValidator
from .types import (
    DEFAULT_INSTRUCTION_NAME,
    DEFAULT_SYSTEM_NAME,
    FRONT_MATTER_DELIMITER,
    SEGMENT_SEPARATOR,
    TEMPLATE_EXTENSIONS,
    IssueSeverity,
    PromptOperation,
    PromptScope,
    PromptSegment,
    VariableMapping,
)

__all__ = [
    "ANY_PLACEHOLDER_PATTERN",
    "DEFAULT_INSTRUCTION_NAME",
    "DEFAULT_SYSTEM_NAME",
    "FRONT_MATTER_DELIMITER",
    "SEGMENT_SEPARATOR",
    "TEMPLATE_EXTENSIONS",
    "VALID_NAME_PATTERN",
    "EmptyTemplateError",
    "InvalidPromptReferenceError",
    "InvalidTemplateError",
    "IssueSeverity",
    "MissingVariableError",
    "PromptBuilder",
    "PromptContext",
    "PromptDecodeError",
    "PromptError",
    "PromptFileNotFoundError",
    "PromptIssue",
    "PromptLoader",
    "PromptMetadata",
    "PromptOperation",
    "PromptRef",
    "PromptRenderer",
    "PromptRepository",
    "PromptRequest",
    "PromptScope",
    "PromptSegment",
    "PromptTemplate",
    "PromptValidationError",
    "PromptValidationResult",
    "PromptValidator",
    "RenderedPrompt",
    "RenderedSegment",
    "UnknownPlaceholderError",
    "VariableMapping",
]
