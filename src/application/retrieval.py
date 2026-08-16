"""Retrieval, assembled and seeded.

Stage-13 publishes a retriever that answers a :class:`RetrievalQuery`. Nothing
before this layer ever built one, and nothing before this layer decided what a
rule asks the corpus. Both belong here.

Assembly is the corpus, the graph and the indexes, in that order::

    JsonlKnowledgeRepository -> GraphBuilder -> KnowledgeGraph
                             -> GraphRagRetriever -> build_index()

No database is involved. Stage-13 takes a :class:`~src.graph.models.KnowledgeGraph`
rather than a store, so the graph is built in the process and Neo4j stays where
Stage-12 left it: an optional persistence backend, off this path entirely.

Building reads every dataset, so it happens once. A service holds the built
retriever for its lifetime and a query costs a lookup. There is no reload: the
index can be written but Stage-13 publishes no way to read one back, so
persisting it would only produce a file nothing opens.

Seeding is two small functions, deliberately separate from the service so they
can be checked without a corpus. An existing rule asks with its resolved
identifiers, its resolved ECS fields and its query text; a requirement asks with
its text alone, because nothing has been parsed and there is nothing to resolve.
A rule whose format states no single query expression — Sigma keeps its
detection in named blocks — contributes no text and asks on identifiers alone.
That is reported, not repaired: inventing a query from a Sigma body would be
this layer translating a rule format, which is Stage-08's work and not done
here.

Nothing degrades. A missing dataset, a malformed record or an unbuilt index
raises where it happens.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Final, final

from src.context.models import RuleContext
from src.graph.graph_builder import GraphBuilder
from src.graphrag.config import GraphRagSettings
from src.graphrag.interfaces import Retriever
from src.graphrag.models import RetrievalQuery, RetrievalResult
from src.graphrag.retriever import GraphRagRetriever
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository
from src.mapping.models import MappedEntities

DEFAULT_SETTINGS: Final[GraphRagSettings] = GraphRagSettings()
"""Stage-13's own defaults.

Stage-05's configuration is frozen and carries no ``graphrag`` section, so the
settings are taken as Stage-13 states them rather than invented here or added to
a configuration file this layer is not allowed to change.
"""


def _ordered(values: Iterable[str | None]) -> tuple[str, ...]:
    """Return the stated values without blanks or repeats, in first-seen order.

    Order is preserved because retrieval seeds are reported back in the order
    they were given, and a package whose seed order changed between runs over
    the same rule would not be reproducible.
    """
    return tuple(dict.fromkeys(value for value in values if value))


def rule_query(rule: RuleContext, mappings: MappedEntities, *, top_k: int) -> RetrievalQuery:
    """Return what an existing rule asks the corpus."""
    resolved = mappings.resolved
    return RetrievalQuery(
        text=rule.query or "",
        entity_ids=_ordered(entity.canonical_id for entity in resolved),
        canonical_fields=_ordered(entity.canonical_field for entity in resolved),
        max_results=top_k,
    )


def requirement_query(requirement: str, *, top_k: int) -> RetrievalQuery:
    """Return what a stated detection requirement asks the corpus.

    No identifiers and no fields. Nothing has been parsed, extracted or mapped,
    so there is nothing resolved to ask with.
    """
    return RetrievalQuery(text=requirement, max_results=top_k)


@final
class RetrievalService:
    """Holds one built retriever and asks it what a request needs."""

    __slots__ = ("_retriever", "_settings")

    def __init__(self, retriever: Retriever, settings: GraphRagSettings) -> None:
        """Hold a retriever that is already built."""
        self._retriever = retriever
        self._settings = settings

    @classmethod
    def build(
        cls,
        knowledge_dir: Path,
        settings: GraphRagSettings | None = None,
    ) -> RetrievalService:
        """Assemble the corpus, the graph and the indexes, and return the service.

        Expensive, and meant to be called once. Every dataset under
        ``knowledge_dir`` is read, chunked and indexed before this returns.
        """
        resolved = settings if settings is not None else DEFAULT_SETTINGS
        repository = JsonlKnowledgeRepository.from_root(knowledge_dir)
        graph = GraphBuilder.over(repository).build()
        retriever = GraphRagRetriever(repository, graph, resolved)
        retriever.build_index()
        return cls(retriever, resolved)

    @classmethod
    def of(
        cls,
        retriever: Retriever,
        settings: GraphRagSettings | None = None,
    ) -> RetrievalService:
        """Wrap a retriever built elsewhere, without building anything."""
        return cls(retriever, settings if settings is not None else DEFAULT_SETTINGS)

    @property
    def settings(self) -> GraphRagSettings:
        """Return the settings queries are seeded from."""
        return self._settings

    def for_rule(self, rule: RuleContext, mappings: MappedEntities) -> RetrievalResult:
        """Return what the corpus says about an existing rule."""
        return self._retriever.retrieve(rule_query(rule, mappings, top_k=self._settings.top_k))

    def for_requirement(self, requirement: str) -> RetrievalResult:
        """Return what the corpus says about a stated detection requirement."""
        return self._retriever.retrieve(
            requirement_query(requirement, top_k=self._settings.top_k)
        )
