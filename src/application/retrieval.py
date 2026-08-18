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
can be checked without a corpus. An existing rule asks with the identifiers the
corpus is keyed by, its resolved ECS fields and its query text; a requirement
asks with its text alone, because nothing has been parsed and there is nothing
to resolve. A rule whose format states no single query expression — Sigma keeps
its detection in named blocks — contributes no text and asks on identifiers
alone. That is reported, not repaired: inventing a query from a Sigma body would
be this layer translating a rule format, which is Stage-08's work and not done
here.

Resolved and keyable are different questions, and only the second one seeds.
Stage-10 resolves a severity because ``medium`` is a real member of a closed
vocabulary; it resolves a private network because ``10.0.0.0/8`` is a real
network. Both are correct mappings and neither names anything the corpus holds,
so asking Stage-13 to look them up produces an unresolved seed, a context
warning, and an entry in the uncertainty ledger that the model is then obliged
to carry — for a value no record could ever have answered to.
:data:`CORPUS_KEYED_TYPES` states which canonical types name a corpus object.

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
from src.mapping.types import CanonicalType

DEFAULT_SETTINGS: Final[GraphRagSettings] = GraphRagSettings()
"""Stage-13's own defaults.

Stage-05's configuration is frozen and carries no ``graphrag`` section, so the
settings are taken as Stage-13 states them rather than invented here or added to
a configuration file this layer is not allowed to change.
"""

CORPUS_KEYED_TYPES: Final[frozenset[CanonicalType]] = frozenset(
    {
        CanonicalType.ATTACK_TECHNIQUE_REFERENCE,
        CanonicalType.ATTACK_TACTIC_REFERENCE,
        CanonicalType.ATTACK_GROUP_REFERENCE,
        CanonicalType.ATTACK_SOFTWARE_REFERENCE,
        CanonicalType.CVE_REFERENCE,
    }
)
"""The canonical types whose identifier names something the corpus can hold.

Not a new vocabulary. Each member is one of Stage-10's reference types, each
corresponds to a member of Stage-11's :class:`~src.knowledge.models.types.ReferenceKind`
— the vocabulary that already states what may be resolved against the corpus —
and each corresponds to a node type Stage-12 builds:

===============================  ==========================  ====================
Stage-10 canonical type          Stage-11 reference kind     Stage-12 node type
===============================  ==========================  ====================
``ATTACK_TECHNIQUE_REFERENCE``   ``ATTACK_TECHNIQUE``        ``TECHNIQUE``
``ATTACK_TACTIC_REFERENCE``      ``ATTACK_TACTIC``           ``TACTIC``
``ATTACK_GROUP_REFERENCE``       ``ATTACK_GROUP``            ``GROUP``
``ATTACK_SOFTWARE_REFERENCE``    ``ATTACK_SOFTWARE``         ``SOFTWARE``
``CVE_REFERENCE``                ``CVE``                     ``EXTERNAL_REFERENCE``
===============================  ==========================  ====================

Every other canonical type that carries an identifier describes a value the rule
matched on rather than an object the corpus describes: a severity, a rule
status, an address, a network, a port, an event id, a hash, a security
identifier. Those remain fully present as entities, as mappings and in the
context — they are simply not questions Stage-13 can ask.

``ATTACK_TACTIC_REFERENCE`` is listed although the bundled MITRE corpus states
no tactic records, so nothing currently answers to a ``TA`` identifier. The
membership describes the kind of thing the identifier is, not what the corpus
happens to hold today; a tactic identifier is exactly as keyable as a technique
identifier, and the absent records are a corpus gap recorded elsewhere.
"""


def _ordered(values: Iterable[str | None]) -> tuple[str, ...]:
    """Return the stated values without blanks or repeats, in first-seen order.

    Order is preserved because retrieval seeds are reported back in the order
    they were given, and a package whose seed order changed between runs over
    the same rule would not be reproducible.
    """
    return tuple(dict.fromkeys(value for value in values if value))


def rule_query(rule: RuleContext, mappings: MappedEntities, *, top_k: int) -> RetrievalQuery:
    """Return what an existing rule asks the corpus.

    The identifiers are narrowed to those naming something the corpus can hold;
    the fields are not narrowed, because only the field mapper sets
    ``canonical_field`` and every value it sets is an ECS field name.
    """
    resolved = mappings.resolved
    return RetrievalQuery(
        text=rule.query or "",
        entity_ids=_ordered(
            entity.canonical_id
            for entity in resolved
            if entity.canonical_type in CORPUS_KEYED_TYPES
        ),
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
