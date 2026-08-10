"""Knowledge resolver.

Resolution of aliases, version differences and canonical identifiers.
"""

from __future__ import annotations

from .reference_resolver import KIND_SOURCES, DefaultKnowledgeResolver

__all__ = ["KIND_SOURCES", "DefaultKnowledgeResolver"]
