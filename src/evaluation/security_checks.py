"""Security-specific checks.

Verifies that the retrieval layer keeps the corpus's gaps visible rather than
papering over them.

These are not quality metrics. They are safety properties: an unresolved
identifier must not acquire a graph node, a missing tactic must not be
manufactured, and an ambiguous identifier must not be silently narrowed to one
candidate. A system that scored perfectly on relevance while failing these would
be worse than useless, because its confident answers would be fabricated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from src.graph.models import KnowledgeGraph
from src.graph.types import NodeType, RelationshipType
from src.graphrag.models import RetrievalQuery, RetrievalResult
from src.graphrag.retriever import GraphRagRetriever
from src.graphrag.types import RetrievalMode

from .models import SecurityFinding


@final
@dataclass(frozen=True, slots=True)
class SecurityEvaluator:
    """Runs the safety expectations against the live system."""

    retriever: GraphRagRetriever
    graph: KnowledgeGraph

    def evaluate(self) -> tuple[SecurityFinding, ...]:
        """Return every security finding, in a fixed order."""
        return (
            *self._unresolved("T1562"),
            *self._unresolved("T1562.001"),
            *self._missing_tactic("TA0011"),
            *self._ambiguous("M1013"),
            *self._no_fabricated_field_edges(),
        )

    def _unresolved(self, identifier: str) -> tuple[SecurityFinding, ...]:
        """Check that an undefined technique gains no node and no graph evidence."""
        result = self.retriever.retrieve(
            RetrievalQuery(text=identifier, entity_ids=(identifier,), max_results=10)
        )
        seed = self._seed(result, identifier)
        node_absent = not any(
            node.properties.get("attackId", "").upper() == identifier.upper()
            for node in self.graph.nodes_of(NodeType.TECHNIQUE)
        )
        graph_evidence = sum(1 for item in result.items if "graph" in [m.value for m in item.methods])
        text_items = sum(1 for item in result.items if "text" in [m.value for m in item.methods])
        return (
            SecurityFinding(
                "unresolved_seed_reported",
                identifier,
                seed is not None and seed.status == "unresolved",
                f"seed status={seed.status if seed else 'absent'}",
            ),
            SecurityFinding(
                "no_fabricated_technique_node",
                identifier,
                node_absent,
                "no Technique node carries this identifier",
            ),
            SecurityFinding(
                "no_fabricated_graph_evidence",
                identifier,
                graph_evidence == 0,
                f"{graph_evidence} items carried graph evidence",
            ),
            SecurityFinding(
                "text_evidence_still_available",
                identifier,
                text_items > 0,
                f"{text_items} items returned via text",
            ),
        )

    def _missing_tactic(self, identifier: str) -> tuple[SecurityFinding, ...]:
        """Check that a tactic the snapshot lacks is never manufactured."""
        result = self.retriever.retrieve(
            RetrievalQuery(
                text=identifier, entity_ids=(identifier,), mode=RetrievalMode.GRAPH, max_results=10
            )
        )
        seed = self._seed(result, identifier)
        tactic_nodes = self.graph.node_counts()[NodeType.TACTIC]
        belongs_to = len(self.graph.relationships_of(RelationshipType.BELONGS_TO))
        return (
            SecurityFinding(
                "missing_tactic_unresolved",
                identifier,
                seed is not None and seed.status == "unresolved",
                f"seed status={seed.status if seed else 'absent'}",
            ),
            SecurityFinding(
                "no_tactic_nodes_fabricated",
                identifier,
                tactic_nodes == 0,
                f"{tactic_nodes} Tactic nodes in graph",
            ),
            SecurityFinding(
                "no_belongs_to_edges_fabricated",
                identifier,
                belongs_to == 0,
                f"{belongs_to} BELONGS_TO edges in graph",
            ),
        )

    def _ambiguous(self, identifier: str) -> tuple[SecurityFinding, ...]:
        """Check that an ambiguous identifier stays ambiguous."""
        result = self.retriever.retrieve(
            RetrievalQuery(
                text=identifier, entity_ids=(identifier,), mode=RetrievalMode.GRAPH, max_results=10
            )
        )
        seed = self._seed(result, identifier)
        candidates = seed.node_ids if seed else ()
        domains = {item.rsplit(":", 2)[-2] for item in candidates if item.count(":") >= 2}
        return (
            SecurityFinding(
                "ambiguity_reported",
                identifier,
                seed is not None and seed.status == "ambiguous",
                f"seed status={seed.status if seed else 'absent'}",
            ),
            SecurityFinding(
                "all_candidates_preserved",
                identifier,
                len(candidates) == 2,
                f"candidates={list(candidates)}",
            ),
            SecurityFinding(
                "no_domain_collapsed",
                identifier,
                len(domains) == 2,
                f"domains={sorted(domains)}",
            ),
            SecurityFinding(
                "no_arbitrary_selection",
                identifier,
                result.statistics.graph_candidates == 0,
                f"{result.statistics.graph_candidates} graph candidates from an ambiguous seed",
            ),
        )

    def _no_fabricated_field_edges(self) -> tuple[SecurityFinding, ...]:
        """Check that no rule-to-field relationship was invented."""
        uses_field = len(self.graph.relationships_of(RelationshipType.USES_FIELD))
        return (
            SecurityFinding(
                "no_fabricated_uses_field_edges",
                "USES_FIELD",
                uses_field == 0,
                f"{uses_field} USES_FIELD edges; corpus states none",
            ),
        )

    def _seed(self, result: RetrievalResult, identifier: str) -> object:
        """Return the seed report for an identifier, or ``None``."""
        for seed in result.seeds:
            if seed.value.strip().upper() == identifier.strip().upper():
                return seed
        return None
