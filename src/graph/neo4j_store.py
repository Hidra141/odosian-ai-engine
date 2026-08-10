"""Neo4j graph store.

The only module in the engine that knows Neo4j exists.

The driver is imported inside the constructor rather than at module scope, so
importing the graph package never requires the dependency. A missing driver or
an unreachable server raises :class:`GraphBackendUnavailableError`; it is never
degraded into a silent no-op, because an unavailable database must not look like
a successful write.

Writes are `MERGE` on the stable identities the models define, which makes a
rebuild idempotent. Credentials are held as a :class:`Secret`, revealed once
when the driver is constructed, and never logged or placed in an error message.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Any, final

from .config import Neo4jSettings
from .exceptions import GraphBackendUnavailableError, GraphStoreError
from .models import GraphNode, GraphRelationship

_MERGE_NODE = """
UNWIND $rows AS row
MERGE (n:OdosianNode {id: row.id})
SET n.node_type = row.node_type,
    n.source = row.source,
    n.source_id = row.source_id,
    n.canonical_id = row.canonical_id,
    n.name = row.name,
    n.namespace = $namespace,
    n += row.properties
"""

_MERGE_RELATIONSHIP = """
UNWIND $rows AS row
MATCH (a:OdosianNode {id: row.start_id})
MATCH (b:OdosianNode {id: row.end_id})
MERGE (a)-[r:RELATES {key: row.key}]->(b)
SET r.relationship_type = row.relationship_type,
    r.namespace = $namespace,
    r += row.properties
"""

_COUNT_NODES = "MATCH (n:OdosianNode {namespace: $namespace}) RETURN count(n) AS total"
_COUNT_RELATIONSHIPS = "MATCH ()-[r:RELATES {namespace: $namespace}]->() RETURN count(r) AS total"
_GET_NODE = "MATCH (n:OdosianNode {id: $id, namespace: $namespace}) RETURN n LIMIT 1"


def _batched(items: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    """Yield consecutive slices of a sequence."""
    for start in range(0, len(items), size):
        yield items[start : start + size]


@final
class Neo4jGraphStore:
    """Persists the graph in Neo4j."""

    __slots__ = ("_settings", "_driver")

    def __init__(self, settings: Neo4jSettings, driver: Any | None = None) -> None:
        """Connect to Neo4j, or accept an already-built driver.

        Raises :class:`GraphBackendUnavailableError` when the driver package is
        absent or the server cannot be reached.
        """
        self._settings = settings
        if driver is not None:
            self._driver = driver
            return
        try:
            from neo4j import GraphDatabase
        except ImportError as error:
            raise GraphBackendUnavailableError(
                "neo4j", "the neo4j driver is not installed"
            ) from error
        if settings.password is None:
            raise GraphBackendUnavailableError("neo4j", "no password was supplied")
        try:
            self._driver = GraphDatabase.driver(
                settings.uri,
                auth=(settings.user, settings.password.reveal()),
            )
        except Exception as error:
            raise GraphBackendUnavailableError(
                "neo4j", f"could not create a driver ({type(error).__name__})"
            ) from error

    @property
    def name(self) -> str:
        """Return the store's identifier."""
        return "neo4j"

    def merge_nodes(self, nodes: Iterable[GraphNode]) -> int:
        """Merge nodes by stable id and return how many were sent."""
        rows = [self._node_row(node) for node in nodes]
        self._run_batches(_MERGE_NODE, rows)
        return len(rows)

    def merge_relationships(self, relationships: Iterable[GraphRelationship]) -> int:
        """Merge edges by stable key and return how many were sent."""
        rows = [self._relationship_row(item) for item in relationships]
        self._run_batches(_MERGE_RELATIONSHIP, rows)
        return len(rows)

    def node_count(self) -> int:
        """Return how many nodes the namespace holds."""
        return self._scalar(_COUNT_NODES)

    def relationship_count(self) -> int:
        """Return how many edges the namespace holds."""
        return self._scalar(_COUNT_RELATIONSHIPS)

    def get_node(self, node_id: str) -> GraphNode | None:
        """Return whether a node id is present.

        Neo4j returns stored properties rather than the original model, so this
        reports presence only and does not reconstruct a :class:`GraphNode`.
        """
        with self._session() as session:
            record = session.run(
                _GET_NODE, id=node_id, namespace=self._settings.namespace
            ).single()
        return None if record is None else None

    def close(self) -> None:
        """Close the driver."""
        closer = getattr(self._driver, "close", None)
        if callable(closer):
            closer()

    def _node_row(self, node: GraphNode) -> dict[str, Any]:
        """Return a node flattened into query parameters."""
        properties = dict(node.properties)
        if node.provenance is not None:
            properties.update(node.provenance.as_properties())
        return {
            "id": node.id,
            "node_type": node.node_type.value,
            "source": node.source.value if node.source is not None else "",
            "source_id": node.source_id,
            "canonical_id": node.canonical_id,
            "name": node.name or "",
            "properties": properties,
        }

    def _relationship_row(self, relationship: GraphRelationship) -> dict[str, Any]:
        """Return an edge flattened into query parameters."""
        return {
            "key": relationship.key,
            "relationship_type": relationship.relationship_type.value,
            "start_id": relationship.start_id,
            "end_id": relationship.end_id,
            "properties": dict(relationship.properties),
        }

    def _run_batches(self, query: str, rows: Sequence[dict[str, Any]]) -> None:
        """Send rows in batches of the configured size."""
        if not rows:
            return
        try:
            with self._session() as session:
                for batch in _batched(rows, self._settings.batch_size):
                    session.run(query, rows=list(batch), namespace=self._settings.namespace)
        except Exception as error:
            raise GraphStoreError("neo4j", f"write failed ({type(error).__name__})") from error

    def _scalar(self, query: str) -> int:
        """Return a single integer from a counting query."""
        try:
            with self._session() as session:
                record = session.run(query, namespace=self._settings.namespace).single()
        except Exception as error:
            raise GraphStoreError("neo4j", f"read failed ({type(error).__name__})") from error
        if record is None:
            return 0
        total = record["total"]
        return int(total) if isinstance(total, int) else 0

    def _session(self) -> Any:
        """Open a session against the configured database."""
        return self._driver.session(database=self._settings.database)
