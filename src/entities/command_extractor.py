"""Command extraction.

Extracts command lines and command-line arguments.

Command lines are never tokenised. Splitting a command line into arguments
requires knowing the quoting and escaping rules of the shell that will run it,
and getting that wrong invents arguments the rule never mentioned. Argument
entities therefore come only from fields that already hold one argument per
element, such as ECS ``process.args``.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from .base_extractor import FieldTable, route_fields
from .models import Entity, ExtractionContext
from .types import EntityType

_FIELDS: Final[FieldTable] = MappingProxyType(
    {
        # Sigma / Windows
        "commandline": EntityType.COMMAND_LINE,
        "parentcommandline": EntityType.COMMAND_LINE,
        "processcommandline": EntityType.COMMAND_LINE,
        "scriptblocktext": EntityType.COMMAND_LINE,
        "command": EntityType.COMMAND_LINE,
        # ECS
        "process.command_line": EntityType.COMMAND_LINE,
        "process.parent.command_line": EntityType.COMMAND_LINE,
        "process.args": EntityType.COMMAND_ARGUMENT,
        "process.parent.args": EntityType.COMMAND_ARGUMENT,
        "args": EntityType.COMMAND_ARGUMENT,
    }
)


@final
class CommandExtractor:
    """Extracts command lines and arguments."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this extractor's identifier."""
        return "command"

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        return (EntityType.COMMAND_LINE, EntityType.COMMAND_ARGUMENT)

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the commands and arguments found in the rule."""
        return tuple(route_fields(context, _FIELDS, extractor=self.name))
