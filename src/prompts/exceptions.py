"""Prompt management exceptions.

Error types raised while locating, reading, validating or rendering prompt
templates.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path


class PromptError(Exception):
    """Base class for every prompt management failure."""


class InvalidPromptReferenceError(PromptError):
    """Raised when a prompt reference cannot address a file safely."""

    def __init__(self, name: str, reason: str) -> None:
        """Record the rejected template name and why it was rejected."""
        super().__init__(f"Invalid prompt reference {name!r}: {reason}")
        self.name = name
        self.reason = reason


class PromptFileNotFoundError(PromptError):
    """Raised when no file backs a prompt reference."""

    def __init__(self, reference: str, searched: Sequence[Path]) -> None:
        """Record the reference and every path that was tried."""
        locations = ", ".join(str(path) for path in searched)
        super().__init__(f"No prompt file found for {reference}; searched: {locations}")
        self.reference = reference
        self.searched = tuple(searched)


class PromptDecodeError(PromptError):
    """Raised when a prompt file cannot be read as text."""

    def __init__(self, path: Path, reason: str) -> None:
        """Record the unreadable file and the underlying reason."""
        super().__init__(f"Failed to read prompt file {path}: {reason}")
        self.path = path
        self.reason = reason


class InvalidTemplateError(PromptError):
    """Raised when a template's structure or front matter is unusable."""

    def __init__(self, path: Path, reason: str) -> None:
        """Record the malformed file and what is wrong with it."""
        super().__init__(f"Invalid prompt template {path}: {reason}")
        self.path = path
        self.reason = reason


class EmptyTemplateError(PromptError):
    """Raised when a template carries no body text."""

    def __init__(self, path: Path) -> None:
        """Record the template that turned out to be empty."""
        super().__init__(f"Prompt template is empty: {path}")
        self.path = path


class MissingVariableError(PromptError):
    """Raised when a template placeholder has no supplied value."""

    def __init__(self, template: str, names: Sequence[str]) -> None:
        """Record the template and every placeholder left unresolved."""
        joined = ", ".join(names)
        super().__init__(f"Template {template!r} is missing values for: {joined}")
        self.template = template
        self.names = tuple(names)


class UnknownPlaceholderError(PromptError):
    """Raised when a template uses a placeholder it does not declare."""

    def __init__(self, template: str, names: Sequence[str]) -> None:
        """Record the template and every undeclared placeholder."""
        joined = ", ".join(names)
        super().__init__(f"Template {template!r} uses undeclared placeholders: {joined}")
        self.template = template
        self.names = tuple(names)


class PromptValidationError(PromptError):
    """Raised when a template fails validation."""

    def __init__(self, messages: Sequence[str]) -> None:
        """Record every validation message produced by the validator."""
        super().__init__("Prompt validation failed: " + "; ".join(messages))
        self.messages = tuple(messages)
