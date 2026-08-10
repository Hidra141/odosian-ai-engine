"""Knowledge interfaces.

Contracts used by knowledge providers.
"""

from __future__ import annotations

from .protocols import (
    KnowledgeLoader,
    KnowledgeNormalizer,
    KnowledgeRepository,
    KnowledgeResolver,
)

__all__ = [
    "KnowledgeLoader",
    "KnowledgeNormalizer",
    "KnowledgeRepository",
    "KnowledgeResolver",
]
