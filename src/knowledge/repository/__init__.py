"""Knowledge repository.

Unified query interface over the loaded knowledge records.
"""

from __future__ import annotations

from .jsonl_repository import JsonlKnowledgeRepository, SourceIndex

__all__ = ["JsonlKnowledgeRepository", "SourceIndex"]
