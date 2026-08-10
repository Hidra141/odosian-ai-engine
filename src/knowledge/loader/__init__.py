"""Knowledge loader.

Reading of knowledge resources from the JSONL datasets.
"""

from __future__ import annotations

from .jsonl_loader import ENVELOPE_KEYS, JsonlKnowledgeLoader
from .layout import DATASET_SUFFIX, CorpusLayout

__all__ = [
    "DATASET_SUFFIX",
    "ENVELOPE_KEYS",
    "CorpusLayout",
    "JsonlKnowledgeLoader",
]
