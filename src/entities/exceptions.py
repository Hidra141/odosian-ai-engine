"""Entity extraction exceptions.

Every failure leaving this package is one of these types.
"""

from __future__ import annotations

from collections.abc import Sequence

from .types import EntityType


class EntityExtractionError(Exception):
    """Base class for every entity extraction failure."""


class UnsupportedEntityError(EntityExtractionError):
    """No registered extractor produces the requested entity type."""

    def __init__(self, entity_type: EntityType, supported: Sequence[EntityType]) -> None:
        """Record the requested type and what the registry can produce."""
        names = ", ".join(sorted(item.value for item in supported)) or "none"
        super().__init__(
            f"No extractor produces {entity_type.value!r}; registered types: {names}"
        )
        self.entity_type = entity_type
        self.supported = tuple(supported)


class ExtractionFailureError(EntityExtractionError):
    """An extractor failed while reading a rule."""

    def __init__(self, extractor: str, reason: str) -> None:
        """Record which extractor failed and why."""
        super().__init__(f"Extractor {extractor!r} failed: {reason}")
        self.extractor = extractor
        self.reason = reason
