"""Prompt management types.

Type definitions and naming conventions used across the prompt package.

The constants below name *files and directories*, never prompt text. Prompt
content lives exclusively in the ``prompts/`` resource tree.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final

type VariableMapping = Mapping[str, str]

TEMPLATE_EXTENSIONS: Final[tuple[str, ...]] = (".md", ".txt")
FRONT_MATTER_DELIMITER: Final[str] = "---"
DEFAULT_SYSTEM_NAME: Final[str] = "system"
DEFAULT_INSTRUCTION_NAME: Final[str] = "instruction"
SEGMENT_SEPARATOR: Final[str] = "\n\n"


class PromptOperation(StrEnum):
    """An operation the engine can be asked to perform."""

    ANALYZE = "analyze"
    ENHANCE = "enhance"
    GENERATE = "generate"


class PromptScope(StrEnum):
    """A subdirectory of the ``prompts/`` resource tree."""

    ANALYZE = "analyze"
    ENHANCE = "enhance"
    GENERATE = "generate"
    SHARED = "shared"
    TEMPLATES = "templates"

    @classmethod
    def for_operation(cls, operation: PromptOperation) -> PromptScope:
        """Return the scope that holds the templates of an operation."""
        return cls(operation.value)


class PromptSegment(StrEnum):
    """The role a rendered template plays in the final prompt."""

    SYSTEM = "system"
    INSTRUCTION = "instruction"


class IssueSeverity(StrEnum):
    """Whether a validation issue blocks use of a template."""

    ERROR = "error"
    WARNING = "warning"
