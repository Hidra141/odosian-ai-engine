"""Prompt location.

Resolves a :class:`PromptRef` to a file inside the ``prompts/`` resource tree
and returns the loaded template.

The repository reads from disk on every call. Nothing is cached, so editing a
template takes effect on the next build without restarting anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .exceptions import InvalidPromptReferenceError, PromptFileNotFoundError
from .prompt_loader import PromptLoader
from .prompt_models import PromptRef, PromptTemplate
from .types import TEMPLATE_EXTENSIONS, PromptOperation, PromptScope

_FORBIDDEN_FRAGMENTS = ("/", "\\", "..")


@dataclass(frozen=True, slots=True)
class PromptRepository:
    """Locate and load templates under one prompts directory."""

    root: Path
    loader: PromptLoader = field(default_factory=PromptLoader)

    def resolve(self, ref: PromptRef) -> Path:
        """Return the file backing a reference, trying each supported extension."""
        _check_name(ref.name)
        directory = self.root / ref.scope.value
        candidates = tuple(directory / f"{ref.name}{suffix}" for suffix in TEMPLATE_EXTENSIONS)
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        raise PromptFileNotFoundError(str(ref), candidates)

    def get(self, ref: PromptRef) -> PromptTemplate:
        """Load the template a reference points at."""
        return self.loader.load(self.resolve(ref))

    def exists(self, ref: PromptRef) -> bool:
        """Return whether a file backs the reference."""
        try:
            self.resolve(ref)
        except (PromptFileNotFoundError, InvalidPromptReferenceError):
            return False
        return True

    def list_scope(self, scope: PromptScope) -> tuple[PromptRef, ...]:
        """Return a reference for every template file in one scope."""
        directory = self.root / scope.value
        if not directory.is_dir():
            return ()
        refs = [
            PromptRef(scope, entry.stem)
            for entry in sorted(directory.iterdir())
            if entry.is_file() and entry.suffix in TEMPLATE_EXTENSIONS
        ]
        return tuple(refs)

    def list_operation(self, operation: PromptOperation) -> tuple[PromptRef, ...]:
        """Return a reference for every template belonging to one operation."""
        return self.list_scope(PromptScope.for_operation(operation))


def _check_name(name: str) -> None:
    """Reject a template name that could address a file outside its scope."""
    if not name.strip():
        raise InvalidPromptReferenceError(name, "name must not be empty")
    for fragment in _FORBIDDEN_FRAGMENTS:
        if fragment in name:
            raise InvalidPromptReferenceError(name, f"name must not contain {fragment!r}")
    if Path(name).is_absolute():
        raise InvalidPromptReferenceError(name, "name must not be an absolute path")
