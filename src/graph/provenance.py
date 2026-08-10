"""Graph provenance.

Why a node and an edge exist, carried on the node and the edge.

A security graph is only usable if every claim in it can be traced back to the
line of the dataset that made it. A node records the record it came from; an
edge records the field that stated the reference, the value as written, the
canonical form it was resolved to, and the resolver's verdict.

Nothing here is derived from prose or inference. Every field is copied from a
record or from a Stage-11 resolution result.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from src.knowledge.models.types import KnowledgeSource

from .types import EdgeOrigin


@dataclass(frozen=True, slots=True)
class NodeProvenance:
    """The record a node was built from."""

    source: KnowledgeSource
    source_id: str
    record_id: str
    dataset: str
    line_number: int

    def as_properties(self) -> Mapping[str, str]:
        """Return the provenance flattened for storage on a node."""
        return MappingProxyType(
            {
                "prov_source": self.source.value,
                "prov_source_id": self.source_id,
                "prov_record_id": self.record_id,
                "prov_dataset": self.dataset,
                "prov_line": str(self.line_number),
            }
        )


@dataclass(frozen=True, slots=True)
class RelationshipProvenance:
    """The evidence that an edge exists."""

    source: KnowledgeSource
    source_id: str
    source_field: str
    source_location: str
    original_value: str
    canonical_id: str
    resolution_status: str
    resolution_method: str
    origin: EdgeOrigin
    evidence: str = ""

    def as_properties(self) -> Mapping[str, str]:
        """Return the provenance flattened for storage on a relationship."""
        return MappingProxyType(
            {
                "source": self.source.value,
                "source_id": self.source_id,
                "source_field": self.source_field,
                "source_location": self.source_location,
                "original_value": self.original_value,
                "canonical_id": self.canonical_id,
                "resolution_status": self.resolution_status,
                "resolution_method": self.resolution_method,
                "origin": self.origin.value,
                "evidence": self.evidence,
            }
        )

    @property
    def evidence_key(self) -> str:
        """Return the part of an edge's identity that distinguishes evidence.

        Two rules citing the same technique are two edges. One rule citing it in
        two different fields is also two edges. Collapsing either would lose a
        distinct piece of evidence.
        """
        return f"{self.source.value}|{self.source_id}|{self.source_field}|{self.original_value}"
