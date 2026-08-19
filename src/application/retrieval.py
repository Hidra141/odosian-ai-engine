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

A rule's fields go out in two vocabularies, one per route. Stage-13's graph is
keyed by what the corpus calls a field and its index holds what rules wrote, and
for Sigma those are not the same string: the corpus spells the field
``CommandLine`` in 1,366 of its own records and ``process.command_line`` in
none. Asking both routes in one vocabulary means asking one of them in a
vocabulary it cannot answer in. :func:`rule_query` therefore states the
canonical name for the graph and the rule's own name for the index. Neither is
derived from the other and neither replaces the other.

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

from collections.abc import Iterable, Mapping
from collections.abc import Set as AbstractSet
from pathlib import Path
from types import MappingProxyType
from typing import Final, final

from src.context.models import RuleContext
from src.graph.graph_builder import GraphBuilder
from src.graphrag.config import GraphRagSettings
from src.graphrag.interfaces import Retriever
from src.graphrag.models import RetrievalQuery, RetrievalResult
from src.graphrag.retriever import GraphRagRetriever
from src.knowledge.models.types import KnowledgeSource
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository
from src.mapping.models import MappedEntities, MappedEntity
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


SIGMA_FIELD_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        # Process image
        "image": "process.executable",
        "imagepath": "process.executable",
        "newprocessname": "process.executable",
        "parentimage": "process.parent.executable",
        "parentprocessname": "process.parent.executable",
        "originalfilename": "process.pe.original_file_name",
        # Command line
        "commandline": "process.command_line",
        "processcommandline": "process.command_line",
        "parentcommandline": "process.parent.command_line",
        # File
        "targetfilename": "file.path",
        "sourcefilename": "file.path",
        "filename": "file.name",
        "targetdirectory": "file.directory",
        "currentdirectory": "process.working_directory",
        # Hash
        "md5": "file.hash.md5",
        "sha1": "file.hash.sha1",
        "sha256": "file.hash.sha256",
        "imphash": "file.pe.imphash",
        # Registry
        "targetobject": "registry.path",
        "objectname": "registry.path",
        "valuename": "registry.value",
        "details": "registry.data.strings",
        # Event
        "eventid": "event.code",
        "winlog.event_id": "event.code",
        "provider_name": "event.provider",
        "winlog.provider_name": "event.provider",
        # Network
        "destinationip": "destination.ip",
        "sourceip": "source.ip",
        "destinationport": "destination.port",
        "sourceport": "source.port",
        "destinationhostname": "destination.domain",
        "queryname": "dns.question.name",
        "protocol": "network.protocol",
        # Identity
        "user": "user.name",
        "username": "user.name",
        "subjectusername": "user.name",
        "targetusername": "user.name",
        "targetgroupname": "group.name",
    }
)
"""The corpus's name for a field a rule format spells differently.

Stage-10's alias table records that ``Image`` and ``process.executable`` occupy
one role. It deliberately stops there — it is a table of names, not a schema,
and it does not resolve anything against ECS. This is the other half: which ECS
field documents the role that spelling names, so a question can go out in the
vocabulary the corpus answers in.

**Keyed on the spelling, not on the canonical type**, because a type is a role
and a role spans several fields. ``Image`` and ``ParentImage`` share
``PROCESS_IMAGE_FIELD`` while naming ``process.executable`` and
``process.parent.executable``; ``NETWORK_FIELD`` alone spans seven ECS fields.
The type cannot choose between them and the spelling can.

Only names that mean exactly one ECS field are here. Four groups are left out
on purpose, and each stays exactly as it behaves today:

* ``source``, ``type`` and ``service`` name more than one role, and Stage-10
  already refuses to choose between them.
* ``channel`` and ``logname`` point at ``winlog.channel``, which this corpus
  does not document as a field of its own.
* ``hashes`` is a Sysmon composite carrying several digests at once, so no
  single field answers for it.
* ``scriptblocktext`` belongs to the ``powershell.*`` namespace, which is not
  ECS.

Every entry is checked against the corpus before it is used, so this table can
widen what a rule asks about but can never invent a field.
"""


def _ordered(values: Iterable[str | None]) -> tuple[str, ...]:
    """Return the stated values without blanks or repeats, in first-seen order.

    Order is preserved because retrieval seeds are reported back in the order
    they were given, and a package whose seed order changed between runs over
    the same rule would not be reproducible.
    """
    return tuple(dict.fromkeys(value for value in values if value))


def rule_query(
    rule: RuleContext,
    mappings: MappedEntities,
    *,
    top_k: int,
    ecs_fields: AbstractSet[str] = frozenset(),
) -> RetrievalQuery:
    """Return what an existing rule asks the corpus.

    The identifiers are narrowed to those naming something the corpus can hold.
    The fields are the ones Stage-10 resolved, together with the ones it could
    not resolve that name an ECS field anyway — see :func:`_asks_about_a_field`.

    Those fields are then stated **twice**, because the two routes can only
    answer in different vocabularies. The graph is keyed by what the corpus
    calls a field, so it is asked with :func:`_ecs_name`'s answer. The index
    holds what rules wrote, so it is asked with what this rule wrote. Both lists
    come from one filtered stream and neither is derived from the other, so a
    rule always asks about the same fields — it simply names them the way each
    route can hear.

    Nothing is unioned. A field reaches the graph under one name and the index
    under one name, and where a rule already writes ECS — every Elastic rule —
    the two names are the same string and the two lists are equal.

    ``ecs_fields`` is the set of field names the corpus documents, supplied by
    the service that read it. It defaults to empty, so a caller that has no
    corpus to hand asks exactly what it asked before.
    """
    fields = tuple(
        entity for entity in mappings if _asks_about_a_field(entity, ecs_fields)
    )
    return RetrievalQuery(
        text=rule.query or "",
        entity_ids=_ordered(
            entity.canonical_id
            for entity in mappings.resolved
            if entity.canonical_type in CORPUS_KEYED_TYPES
        ),
        canonical_fields=_ordered(_ecs_name(entity, ecs_fields) for entity in fields),
        lexical_fields=_ordered(entity.canonical_field for entity in fields),
        max_results=top_k,
    )


def _ecs_name(entity: MappedEntity, ecs_fields: AbstractSet[str]) -> str | None:
    """Return the name the corpus knows this field under.

    A rule writes the spelling its own format uses. Elastic writes ECS names, so
    the two are the same string and nothing happens here. Sigma writes Windows
    telemetry — ``Image``, ``CommandLine``, ``EventID`` — and the corpus holds no
    record under any of them, so the question went out in a vocabulary nothing
    could answer in: ``CommandLine`` resolved to nothing, and ``Image`` reached
    the ATT&CK data source of that name rather than ``process.executable``.

    :data:`SIGMA_FIELD_NAMES` supplies the corpus's name for a spelling it
    documents under another. The translation is checked against the corpus
    before it is used, so a table entry can never introduce a field the
    knowledge base does not hold, and a corpus without ECS behaves exactly as it
    did before.

    Only the query is translated. The mapping keeps recording what the rule
    wrote — its value, its source field, its modifiers and its canonical type
    are all untouched — because that is what a reader needs to see the rule as
    its author wrote it.
    """
    name = (entity.canonical_field or "").strip()
    if not name:
        return None
    documented = SIGMA_FIELD_NAMES.get(name.lower())
    if documented is not None and documented in ecs_fields:
        return documented
    return name


def _asks_about_a_field(entity: MappedEntity, ecs_fields: AbstractSet[str]) -> bool:
    """Return whether this mapping names a field the corpus can be asked about.

    Two ways to qualify, and the first is the one that already existed: Stage-10
    resolved the name through its alias table, which is what ``Image`` and
    ``process.executable`` do. Those seed exactly as they did before, whether or
    not ECS carries the name they resolved to.

    The second is C3. An unresolved field name still names a field — the alias
    table is a table of shared spellings, not a list of every field there is —
    and if the corpus documents a field of exactly that name then a record
    exists to answer for it. ``event.action`` is unresolved and real; asking
    about it is as sound as asking about a technique identifier.

    Membership is an exact, case-insensitive lookup in a set read from the
    corpus. Nothing is inferred from a name's shape, so ``auditd.data.a0`` is
    not admitted for being dotted, and nothing is added to Stage-10's table.

    Only the field mapper ever sets ``canonical_field``, so a severity, a
    network, a port or an event id cannot reach this test at all: F2 decides
    those, and it decides them on ``canonical_id``.
    """
    name = (entity.canonical_field or "").strip()
    if not name:
        return False
    return entity.is_resolved or name.lower() in ecs_fields


def ecs_field_names(repository: JsonlKnowledgeRepository) -> frozenset[str]:
    """Return the field names the ECS dataset documents, lower-cased.

    Read from the corpus rather than declared here, so the set is whatever the
    knowledge base actually holds and cannot drift from it. A record that states
    no field name — ECS also ships field-*set* records — contributes nothing.

    A corpus with no ECS dataset returns an empty set, which leaves seeding
    exactly as it was rather than failing a build over an absent optional
    dataset.
    """
    if KnowledgeSource.ECS not in repository.available_sources():
        return frozenset()
    names: list[str] = []
    for record in repository.iterate_source(KnowledgeSource.ECS):
        name = (record.metadata or {}).get("fieldName")
        if isinstance(name, str) and name.strip():
            names.append(name.strip().lower())
    return frozenset(names)


def requirement_query(requirement: str, *, top_k: int) -> RetrievalQuery:
    """Return what a stated detection requirement asks the corpus.

    No identifiers and no fields. Nothing has been parsed, extracted or mapped,
    so there is nothing resolved to ask with.
    """
    return RetrievalQuery(text=requirement, max_results=top_k)


@final
class RetrievalService:
    """Holds one built retriever and asks it what a request needs."""

    __slots__ = ("_retriever", "_settings", "_ecs_fields")

    def __init__(
        self,
        retriever: Retriever,
        settings: GraphRagSettings,
        ecs_fields: AbstractSet[str] = frozenset(),
    ) -> None:
        """Hold a retriever that is already built, and what ECS documents."""
        self._retriever = retriever
        self._settings = settings
        self._ecs_fields = ecs_fields

    @classmethod
    def build(
        cls,
        knowledge_dir: Path,
        settings: GraphRagSettings | None = None,
    ) -> RetrievalService:
        """Assemble the corpus, the graph and the indexes, and return the service.

        Expensive, and meant to be called once. Every dataset under
        ``knowledge_dir`` is read, chunked and indexed before this returns.

        The ECS field names are read from the same repository, on the pass that
        is already happening. No second source of ECS truth is introduced and
        nothing is derived that the corpus does not state.
        """
        resolved = settings if settings is not None else DEFAULT_SETTINGS
        repository = JsonlKnowledgeRepository.from_root(knowledge_dir)
        graph = GraphBuilder.over(repository).build()
        retriever = GraphRagRetriever(repository, graph, resolved)
        retriever.build_index()
        return cls(retriever, resolved, ecs_field_names(repository))

    @classmethod
    def of(
        cls,
        retriever: Retriever,
        settings: GraphRagSettings | None = None,
        ecs_fields: AbstractSet[str] = frozenset(),
    ) -> RetrievalService:
        """Wrap a retriever built elsewhere, without building anything.

        The field names default to none, because a caller supplying its own
        retriever may have no corpus to read them from. A service without them
        seeds exactly the fields Stage-10 resolved, as it did before.
        """
        return cls(
            retriever,
            settings if settings is not None else DEFAULT_SETTINGS,
            ecs_fields,
        )

    @property
    def settings(self) -> GraphRagSettings:
        """Return the settings queries are seeded from."""
        return self._settings

    @property
    def ecs_fields(self) -> AbstractSet[str]:
        """Return the ECS field names this service validates against."""
        return self._ecs_fields

    def for_rule(self, rule: RuleContext, mappings: MappedEntities) -> RetrievalResult:
        """Return what the corpus says about an existing rule."""
        return self._retriever.retrieve(
            rule_query(
                rule,
                mappings,
                top_k=self._settings.top_k,
                ecs_fields=self._ecs_fields,
            )
        )

    def for_requirement(self, requirement: str) -> RetrievalResult:
        """Return what the corpus says about a stated detection requirement."""
        return self._retriever.retrieve(
            requirement_query(requirement, top_k=self._settings.top_k)
        )
