"""Prompt models.

Immutable value objects exchanged inside the prompt package and handed to the
caller. They carry data only: no model reads the filesystem, scans text or
performs substitution.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from .types import (
    PromptOperation,
    PromptScope,
    PromptSegment,
    SEGMENT_SEPARATOR,
    VariableMapping,
)


def _empty_variables() -> VariableMapping:
    """Return an immutable, empty variable mapping."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class PromptRef:
    """The address of one template inside the ``prompts/`` tree."""

    scope: PromptScope
    name: str

    def __str__(self) -> str:
        """Return the reference as ``scope/name``."""
        return f"{self.scope.value}/{self.name}"


@dataclass(frozen=True, slots=True)
class PromptMetadata:
    """Descriptive attributes of a template, from its front matter or its path."""

    name: str
    source: Path
    version: str | None = None
    description: str | None = None
    declared_variables: tuple[str, ...] = ()

    @property
    def declares_variables(self) -> bool:
        """Return whether the template declares its variables explicitly."""
        return bool(self.declared_variables)


@dataclass(frozen=True, slots=True)
class PromptTemplate:
    """A loaded template: its metadata, its body and the placeholders it uses."""

    metadata: PromptMetadata
    body: str
    placeholders: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Return whether the body carries no text."""
        return not self.body.strip()


@dataclass(frozen=True, slots=True)
class PromptContext:
    """Variable values supplied to the prompt from outside this package.

    This package never builds context. It substitutes exactly what it is given;
    assembling the evidence package belongs to the context layer.
    """

    variables: VariableMapping = field(default_factory=_empty_variables)

    @classmethod
    def of(cls, **variables: str) -> PromptContext:
        """Build a context from keyword variables."""
        return cls(MappingProxyType(dict(variables)))

    def with_variables(self, **extra: str) -> PromptContext:
        """Return a copy with additional variables merged over the existing ones."""
        merged: dict[str, str] = {**self.variables, **extra}
        return PromptContext(MappingProxyType(merged))


@dataclass(frozen=True, slots=True)
class PromptRequest:
    """A request to build the prompt for one operation.

    Leaving a reference unset selects the conventional template of the
    operation's own scope.
    """

    operation: PromptOperation
    context: PromptContext = field(default_factory=PromptContext)
    shared_refs: tuple[PromptRef, ...] = ()
    system_ref: PromptRef | None = None
    instruction_ref: PromptRef | None = None


@dataclass(frozen=True, slots=True)
class RenderedSegment:
    """One template after substitution, together with where it came from."""

    segment: PromptSegment
    ref: PromptRef
    source: Path
    text: str
    variables: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RenderedPrompt:
    """A prompt that is ready to be sent by the LLM layer.

    The system and instruction parts are kept apart so a provider can map them
    onto separate fields. :meth:`as_text` is offered for providers that accept a
    single block of text.
    """

    operation: PromptOperation
    system: str
    instruction: str
    segments: tuple[RenderedSegment, ...]
    variables: tuple[str, ...] = ()
    sources: tuple[Path, ...] = ()

    def as_text(self) -> str:
        """Return the system and instruction parts joined into one block."""
        parts = [part for part in (self.system, self.instruction) if part.strip()]
        return SEGMENT_SEPARATOR.join(parts)

    def segment_texts(self) -> Mapping[str, str]:
        """Return the rendered text of each part, addressed by segment name."""
        return MappingProxyType({"system": self.system, "instruction": self.instruction})
