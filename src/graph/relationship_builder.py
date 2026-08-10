"""Relationship building.

Turns the references a record states into edges, or into a recorded reason why
no edge was created.

Every ATT&CK-style reference is resolved by the **Stage-11 resolver**. This
module does not look anything up itself: it reads references out of metadata,
hands them to the resolver, and acts on the verdict. Resolved produces an edge;
unresolved and ambiguous produce a diagnostic entry and nothing else.

Two kinds of reference are read here that Stage-11 does not surface, because its
reader looks for strings and these are not:

* MITRE's ``tactics``, which is a list of objects, not of identifiers
* tag values, which need no corpus lookup at all

Reading them is a literal metadata read. It is not a second resolver: every
identifier still goes through Stage-11 to decide whether a target exists.

Tags become edges to tag nodes without resolution, since a tag is its own
identity. A CVE tag additionally produces an edge to an external reference node,
which records that something was cited without claiming a record describes it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, final

from src.knowledge.models.records import (
    KnowledgeRecord,
    KnowledgeReference,
    NormalizedKnowledgeRecord,
)
from src.knowledge.models.types import KnowledgeSource, ReferenceKind, ResolutionStatus
from src.knowledge.resolver.reference_resolver import DefaultKnowledgeResolver

from .models import GraphNode, GraphRelationship, SkippedEdge, relationship_key
from .node_builder import CVE_NODE_SCHEME, NodeBuilder
from .provenance import RelationshipProvenance
from .types import EdgeOrigin, NodeType, RelationshipType, SkipReason

_DETECTION_FIELDS: Final[frozenset[str]] = frozenset(
    {"mitreTechniques", "mitre.techniqueId", "mitreTechnique"}
)

_TARGET_RELATIONSHIP: Final[dict[NodeType, RelationshipType]] = {
    NodeType.TECHNIQUE: RelationshipType.REFERENCES,
    NodeType.SOFTWARE: RelationshipType.REFERENCES,
    NodeType.GROUP: RelationshipType.REFERENCES,
    NodeType.CAMPAIGN: RelationshipType.REFERENCES,
    NodeType.MITIGATION: RelationshipType.REFERENCES,
    NodeType.DATA_SOURCE: RelationshipType.REFERENCES,
    NodeType.TACTIC: RelationshipType.BELONGS_TO,
}

_CVE_TAG: Final[re.Pattern[str]] = re.compile(r"\Acve[.\-_](?P<year>\d{4})[.\-_](?P<serial>\d{4,})\Z", re.I)

_STAGE11_METHOD: Final[str] = "stage11_reference_resolver"
_LITERAL_METHOD: Final[str] = "literal_metadata"


@dataclass(frozen=True, slots=True)
class EdgeBatch:
    """The edges and extra nodes one record produced, plus what it skipped."""

    relationships: tuple[GraphRelationship, ...] = ()
    extra_nodes: tuple[GraphNode, ...] = ()
    skipped: tuple[SkippedEdge, ...] = ()


@final
class RelationshipBuilder:
    """Builds edges from the references a record states."""

    __slots__ = ("_resolver", "_nodes")

    def __init__(self, resolver: DefaultKnowledgeResolver, nodes: NodeBuilder | None = None) -> None:
        """Build over a Stage-11 resolver; all lookups are delegated to it."""
        self._resolver = resolver
        self._nodes = nodes if nodes is not None else NodeBuilder()

    def build(
        self,
        normalized: NormalizedKnowledgeRecord,
        start_node: GraphNode,
        nodes_by_record: Mapping[str, GraphNode],
    ) -> EdgeBatch:
        """Return the edges a record's references support.

        ``nodes_by_record`` maps a knowledge record's envelope id to the node it
        produced, so a resolved record reaches its node without a scan.
        """
        relationships: list[GraphRelationship] = []
        extra: list[GraphNode] = []
        skipped: list[SkippedEdge] = []

        for reference in self._references(normalized):
            self._resolve_edge(reference, start_node, nodes_by_record, relationships, skipped)

        for tag in self._tags(normalized.record):
            self._tag_edge(tag, normalized.record, start_node, relationships, extra)

        return EdgeBatch(tuple(relationships), tuple(extra), tuple(skipped))

    def _references(self, normalized: NormalizedKnowledgeRecord) -> Iterator[KnowledgeReference]:
        """Yield every reference to resolve, from Stage-11 plus stated tactics."""
        yield from normalized.references
        yield from self._stated_tactics(normalized.record)

    def _stated_tactics(self, record: KnowledgeRecord) -> Iterator[KnowledgeReference]:
        """Yield the tactic identifiers a MITRE technique states.

        Stage-11 reads string members; this field holds objects, so the
        identifiers are read here and resolved by Stage-11 like any other.
        """
        if record.source is not KnowledgeSource.MITRE:
            return
        entries = record.metadata_value("tactics")
        if not isinstance(entries, (list, tuple)):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            value = entry.get("tacticId")
            if isinstance(value, str) and value.strip():
                yield KnowledgeReference(
                    kind=ReferenceKind.ATTACK_TACTIC,
                    value=value.strip().upper(),
                    origin_source=record.source,
                    origin_record_id=record.id,
                    origin_field="tactics.tacticId",
                )

    def _tags(self, record: KnowledgeRecord) -> Sequence[str]:
        """Return the tags a record carries, as written."""
        values = record.metadata_value("tags")
        if not isinstance(values, (list, tuple)):
            return ()
        return tuple(item.strip() for item in values if isinstance(item, str) and item.strip())

    def _resolve_edge(
        self,
        reference: KnowledgeReference,
        start_node: GraphNode,
        nodes_by_record: Mapping[str, GraphNode],
        relationships: list[GraphRelationship],
        skipped: list[SkippedEdge],
    ) -> None:
        """Resolve one reference and add an edge, or record why none was added."""
        record_source = reference.origin_source or start_node.source
        if record_source is None:
            return
        result = self._resolver.resolve(reference)

        if result.status is ResolutionStatus.UNRESOLVED:
            skipped.append(
                SkippedEdge(
                    reason=SkipReason.UNRESOLVED_TARGET,
                    source=record_source,
                    source_id=start_node.source_id,
                    source_field=reference.origin_field,
                    original_value=reference.value,
                    note=result.note,
                )
            )
            return

        if result.status is ResolutionStatus.AMBIGUOUS:
            skipped.append(
                SkippedEdge(
                    reason=SkipReason.AMBIGUOUS_TARGET,
                    source=record_source,
                    source_id=start_node.source_id,
                    source_field=reference.origin_field,
                    original_value=reference.value,
                    candidates=tuple(item.id for item in result.records),
                    note=result.note,
                )
            )
            return

        target = result.record
        if target is None:
            return
        target_node = nodes_by_record.get(target.id)
        if target_node is None:
            skipped.append(
                SkippedEdge(
                    reason=SkipReason.TARGET_NODE_ABSENT,
                    source=record_source,
                    source_id=start_node.source_id,
                    source_field=reference.origin_field,
                    original_value=reference.value,
                    note="resolved record produced no node",
                )
            )
            return

        target_node_id = target_node.id
        relationship_type = self._relationship_type(
            start_node,
            target_node.node_type,
            reference,
        )
        provenance = RelationshipProvenance(
            source=record_source,
            source_id=start_node.source_id,
            source_field=reference.origin_field,
            source_location=f"{record_source.value}:{start_node.source_id}:{reference.origin_field}",
            original_value=reference.value,
            canonical_id=target.metadata_str("techniqueId") or target.metadata_str("id") or "",
            resolution_status=result.status.value,
            resolution_method=_STAGE11_METHOD,
            origin=EdgeOrigin.RESOLVED_REFERENCE,
            evidence=target.id,
        )
        relationships.append(
            GraphRelationship(
                key=relationship_key(start_node.id, relationship_type, target_node_id, provenance),
                relationship_type=relationship_type,
                start_id=start_node.id,
                end_id=target_node_id,
                provenance=provenance,
                properties=provenance.as_properties(),
            )
        )

    def _relationship_type(
        self,
        start_node: GraphNode,
        target_type: NodeType,
        reference: KnowledgeReference,
    ) -> RelationshipType:
        """Return the edge type for a resolved reference.

        A rule that names a technique in a dedicated detection field detects it;
        one that names it in a tag references it. A technique naming its parent
        refines it.
        """
        if (
            start_node.node_type is NodeType.TECHNIQUE
            and target_type is NodeType.TECHNIQUE
            and reference.origin_field == "parentTechniqueId"
        ):
            return RelationshipType.SUBTECHNIQUE_OF
        if (
            target_type is NodeType.TECHNIQUE
            and start_node.node_type in (NodeType.RULE, NodeType.LOLBAS_ENTRY)
            and reference.origin_field in _DETECTION_FIELDS
        ):
            return RelationshipType.DETECTS
        return _TARGET_RELATIONSHIP.get(target_type, RelationshipType.REFERENCES)

    def _tag_edge(
        self,
        tag: str,
        record: KnowledgeRecord,
        start_node: GraphNode,
        relationships: list[GraphRelationship],
        extra: list[GraphNode],
    ) -> None:
        """Add the tag edge, and a CVE reference edge when the tag is one."""
        tag_node = self._nodes.tag_node(tag)
        extra.append(tag_node)
        provenance = RelationshipProvenance(
            source=record.source,
            source_id=record.source_id,
            source_field="tags",
            source_location=f"{record.source.value}:{record.source_id}:tags",
            original_value=tag,
            canonical_id=tag,
            resolution_status="not_applicable",
            resolution_method=_LITERAL_METHOD,
            origin=EdgeOrigin.LITERAL_METADATA,
        )
        relationships.append(
            GraphRelationship(
                key=relationship_key(start_node.id, RelationshipType.HAS_TAG, tag_node.id, provenance),
                relationship_type=RelationshipType.HAS_TAG,
                start_id=start_node.id,
                end_id=tag_node.id,
                provenance=provenance,
                properties=provenance.as_properties(),
            )
        )

        match = _CVE_TAG.match(tag)
        if match is None:
            return
        identifier = f"CVE-{match.group('year')}-{match.group('serial')}"
        external = self._nodes.external_reference_node(CVE_NODE_SCHEME, identifier)
        extra.append(external)
        cve_provenance = RelationshipProvenance(
            source=record.source,
            source_id=record.source_id,
            source_field="tags",
            source_location=f"{record.source.value}:{record.source_id}:tags",
            original_value=tag,
            canonical_id=identifier,
            resolution_status="external",
            resolution_method=_LITERAL_METHOD,
            origin=EdgeOrigin.LITERAL_METADATA,
            evidence="no loaded dataset describes this identifier",
        )
        relationships.append(
            GraphRelationship(
                key=relationship_key(
                    start_node.id, RelationshipType.REFERENCES, external.id, cve_provenance
                ),
                relationship_type=RelationshipType.REFERENCES,
                start_id=start_node.id,
                end_id=external.id,
                provenance=cve_provenance,
                properties=cve_provenance.as_properties(),
            )
        )
