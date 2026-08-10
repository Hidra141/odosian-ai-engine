"""Knowledge normalizer.

Normalisation of field names, values and internal representations.
"""

from __future__ import annotations

from .record_normalizer import DefaultKnowledgeNormalizer
from .references import canonical_identifier, classify_identifier, references_of

__all__ = [
    "DefaultKnowledgeNormalizer",
    "canonical_identifier",
    "classify_identifier",
    "references_of",
]
