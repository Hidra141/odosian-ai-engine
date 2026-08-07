"""Prompt loading.

Reads a template file from disk as UTF-8, separates optional YAML front matter
from the body, and returns a :class:`PromptTemplate`.

Front matter is optional. When present it declares the template's identity and
the variables it is allowed to use::

    ---
    name: analyze-system
    version: "1"
    description: ...
    variables: [RULE, CONTEXT]
    ---

When absent, the name falls back to the file stem and the template is treated as
declaring no variables, which relaxes the undeclared-placeholder check.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from .exceptions import InvalidTemplateError, PromptDecodeError, PromptFileNotFoundError
from .placeholders import find_placeholders
from .prompt_models import PromptMetadata, PromptTemplate
from .types import FRONT_MATTER_DELIMITER


@dataclass(frozen=True, slots=True)
class PromptLoader:
    """Read prompt template files. Holds no state and caches nothing."""

    encoding: str = "utf-8"

    def load(self, path: Path) -> PromptTemplate:
        """Read one template file and return it parsed."""
        text = self._read(path)
        front_matter, body = _split_front_matter(text, path)
        metadata = _build_metadata(front_matter, path)
        return PromptTemplate(
            metadata=metadata,
            body=body,
            placeholders=find_placeholders(body),
        )

    def _read(self, path: Path) -> str:
        """Return the decoded contents of a template file."""
        if not path.is_file():
            raise PromptFileNotFoundError(path.name, (path,))
        try:
            return path.read_text(encoding=self.encoding)
        except UnicodeDecodeError as error:
            raise PromptDecodeError(path, f"not valid {self.encoding}: {error}") from error
        except OSError as error:
            raise PromptDecodeError(path, str(error)) from error


def _split_front_matter(text: str, path: Path) -> tuple[Mapping[str, object] | None, str]:
    """Split optional YAML front matter from the template body."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != FRONT_MATTER_DELIMITER:
        return None, text
    for index in range(1, len(lines)):
        if lines[index].strip() != FRONT_MATTER_DELIMITER:
            continue
        block = "\n".join(lines[1:index])
        body = "\n".join(lines[index + 1 :])
        return _parse_front_matter(block, path), body.lstrip("\n")
    raise InvalidTemplateError(path, "front matter is not terminated")


def _parse_front_matter(block: str, path: Path) -> Mapping[str, object]:
    """Parse a front matter block into a mapping."""
    try:
        parsed = yaml.safe_load(block)
    except yaml.YAMLError as error:
        raise InvalidTemplateError(path, f"front matter is not valid YAML: {error}") from error
    if parsed is None:
        return {}
    if not isinstance(parsed, Mapping):
        raise InvalidTemplateError(path, "front matter must be a mapping")
    return {str(key): value for key, value in parsed.items()}


def _build_metadata(front_matter: Mapping[str, object] | None, path: Path) -> PromptMetadata:
    """Build template metadata from front matter, falling back to the file path."""
    if front_matter is None:
        return PromptMetadata(name=path.stem, source=path)
    return PromptMetadata(
        name=_optional_str(front_matter, "name", path) or path.stem,
        source=path,
        version=_optional_str(front_matter, "version", path),
        description=_optional_str(front_matter, "description", path),
        declared_variables=_variable_names(front_matter, path),
    )


def _optional_str(front_matter: Mapping[str, object], key: str, path: Path) -> str | None:
    """Return a scalar front matter entry as a string, or ``None`` when unset."""
    value = front_matter.get(key)
    if value is None:
        return None
    if isinstance(value, (str, int, float)):
        return str(value)
    raise InvalidTemplateError(path, f"front matter key {key!r} must be a scalar")


def _variable_names(front_matter: Mapping[str, object], path: Path) -> tuple[str, ...]:
    """Return the declared variable names from front matter."""
    value = front_matter.get("variables")
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, Sequence):
        names: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise InvalidTemplateError(path, "front matter 'variables' must hold strings")
            names.append(item.strip())
        return tuple(names)
    raise InvalidTemplateError(path, "front matter 'variables' must be a sequence")
