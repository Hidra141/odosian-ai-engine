"""Node building.

Turns a knowledge record into the node it represents.

The node type comes from what the record says about itself — MITRE's
``objectType``, the dataset a rule came from — never from reading its prose. A
record whose type cannot be established from metadata produces no node rather
than a guessed one.

Identity is the record's own identifier, not its text: an ATT&CK technique is
``T1059.001`` whatever its description says, so a change to the wording of a
record never changes the node it produces.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, final

from src.knowledge.models.records import KnowledgeRecord, NormalizedKnowledgeRecord
from src.knowledge.models.types import KnowledgeSource

from .models import GraphNode, node_id
from .provenance import NodeProvenance
from .types import NodeType, RuleCategory

_MITRE_OBJECT_TYPES: Final[Mapping[str, NodeType]] = MappingProxyType(
    {
        "technique": NodeType.TECHNIQUE,
        "tactic": NodeType.TACTIC,
        "software": NodeType.SOFTWARE,
        "group": NodeType.GROUP,
        "mitigation": NodeType.MITIGATION,
        "campaign": NodeType.CAMPAIGN,
        "data-source": NodeType.DATA_SOURCE,
    }
)

_RULE_CATEGORIES: Final[Mapping[KnowledgeSource, RuleCategory]] = MappingProxyType(
    {
        KnowledgeSource.SIGMA: RuleCategory.SIGMA,
        KnowledgeSource.ELASTIC: RuleCategory.ELASTIC,
    }
)

TAG_NODE_SCHEME: Final[str] = "tag"
CVE_NODE_SCHEME: Final[str] = "cve"


@final
class NodeBuilder:
    """Builds graph nodes from knowledge records."""

    __slots__ = ()

    def build(self, normalized: NormalizedKnowledgeRecord) -> GraphNode | None:
        """Return the node a record represents, or ``None`` when it has no type."""
        record = normalized.record
        if record.source is KnowledgeSource.MITRE:
            return self._mitre(normalized)
        if record.source in _RULE_CATEGORIES:
            return self._rule(normalized)
        if record.source is KnowledgeSource.LOLBAS:
            return self._simple(normalized, NodeType.LOLBAS_ENTRY, record.source_id)
        if record.source is KnowledgeSource.ECS:
            return self._simple(normalized, NodeType.ECS_FIELD, record.source_id)
        return None

    def tag_node(self, value: str) -> GraphNode:
        """Return the node for a tag.

        A tag has no dataset behind it, so the node carries no source and no
        provenance of its own. The edge that points at it carries the evidence.
        """
        token = value.strip()
        return GraphNode(
            id=node_id(None, NodeType.TAG, token),
            node_type=NodeType.TAG,
            source=None,
            source_id=token,
            canonical_id=token,
            name=token,
            properties=MappingProxyType({"scheme": TAG_NODE_SCHEME}),
        )

    def external_reference_node(self, scheme: str, identifier: str) -> GraphNode:
        """Return a node for an identifier no loaded dataset describes.

        It records that something was referenced and nothing more. There is no
        name, no description and no claim that a knowledge record exists for it,
        because none does.
        """
        token = identifier.strip()
        return GraphNode(
            id=node_id(None, NodeType.EXTERNAL_REFERENCE, f"{scheme}:{token}"),
            node_type=NodeType.EXTERNAL_REFERENCE,
            source=None,
            source_id=token,
            canonical_id=f"{scheme}:{token}",
            name=None,
            properties=MappingProxyType({"scheme": scheme, "identifier": token, "described": "false"}),
        )

    def _mitre(self, normalized: NormalizedKnowledgeRecord) -> GraphNode | None:
        """Return the node for a MITRE record, keyed by domain and ATT&CK identifier.

        The identifier alone is not unique across the corpus: ``M1013`` names a
        mitigation in both the enterprise and mobile domains. Keying on the
        identifier alone would merge the two records into one node and discard
        one record's provenance, which is the ambiguity this layer must preserve
        rather than resolve. The record's own ``sourceId`` already carries the
        domain, so it is used as the identity and the bare ATT&CK identifier is
        kept as a property so the graph stays queryable by it.
        """
        record = normalized.record
        object_type = record.metadata_str("objectType")
        node_type = _MITRE_OBJECT_TYPES.get(object_type or "")
        if node_type is None:
            return None
        attack_id = record.metadata_str("techniqueId") or record.metadata_str("id")
        if attack_id is None:
            return None
        properties = {
            "objectType": object_type or "",
            "domain": record.metadata_str("domain") or "",
            "attackId": attack_id,
        }
        return self._node(normalized, node_type, record.source_id, properties)

    def _rule(self, normalized: NormalizedKnowledgeRecord) -> GraphNode | None:
        """Return the node for a detection rule from either rule corpus."""
        record = normalized.record
        category = _RULE_CATEGORIES[record.source]
        canonical = record.metadata_str("ruleId") or record.source_id
        properties = {
            "category": category.value,
            "ruleType": record.metadata_str("type") or "",
            "level": record.metadata_str("level") or record.metadata_str("severity") or "",
            "status": record.metadata_str("status") or record.metadata_str("maturity") or "",
        }
        return self._node(normalized, NodeType.RULE, canonical, properties)

    def _simple(
        self,
        normalized: NormalizedKnowledgeRecord,
        node_type: NodeType,
        canonical: str,
    ) -> GraphNode:
        """Return a node keyed directly by the record's source id."""
        record = normalized.record
        properties = {
            "objectType": record.metadata_str("objectType") or "",
            "fieldSet": record.metadata_str("fieldSet") or "",
            "platform": record.metadata_str("platform") or "",
        }
        return self._node(normalized, node_type, canonical, properties)

    def _node(
        self,
        normalized: NormalizedKnowledgeRecord,
        node_type: NodeType,
        canonical: str,
        properties: dict[str, str],
    ) -> GraphNode:
        """Assemble a node with its provenance and non-empty properties."""
        record = normalized.record
        if normalized.url:
            properties["url"] = normalized.url
        return GraphNode(
            id=node_id(record.source, node_type, canonical),
            node_type=node_type,
            source=record.source,
            source_id=record.source_id,
            canonical_id=canonical,
            name=normalized.title,
            properties=MappingProxyType({k: v for k, v in properties.items() if v}),
            provenance=self._provenance(record),
        )

    def _provenance(self, record: KnowledgeRecord) -> NodeProvenance | None:
        """Return the provenance of the record a node was built from."""
        if record.provenance is None:
            return None
        return NodeProvenance(
            source=record.source,
            source_id=record.source_id,
            record_id=record.id,
            dataset=record.provenance.path.name,
            line_number=record.provenance.line_number,
        )
