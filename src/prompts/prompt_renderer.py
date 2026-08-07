"""Prompt rendering.

Replaces ``{{NAME}}`` placeholders with supplied values.

Substitution is a single pass: a value that itself contains something looking
like a placeholder is inserted literally and never expanded again. Backslashes
and group references inside values carry no special meaning either, because the
replacement is produced by a function rather than a template string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .exceptions import MissingVariableError
from .placeholders import ANY_PLACEHOLDER_PATTERN
from .prompt_models import PromptTemplate
from .types import VariableMapping


@dataclass(frozen=True, slots=True)
class PromptRenderer:
    """Substitute variables into a template body."""

    def render(self, template: PromptTemplate, variables: VariableMapping) -> str:
        """Return the template body with every placeholder replaced.

        Raises :class:`MissingVariableError` listing every placeholder left
        without a value, rather than failing on the first one.
        """
        missing: list[str] = []

        def replace(match: re.Match[str]) -> str:
            name = match.group(1).strip()
            value = variables.get(name)
            if value is None:
                if name not in missing:
                    missing.append(name)
                return match.group(0)
            return value

        rendered = ANY_PLACEHOLDER_PATTERN.sub(replace, template.body)
        if missing:
            raise MissingVariableError(template.metadata.name, missing)
        return rendered

    def missing_variables(
        self,
        template: PromptTemplate,
        variables: VariableMapping,
    ) -> tuple[str, ...]:
        """Return the placeholders of a template that have no supplied value."""
        return tuple(name for name in template.placeholders if name not in variables)
