"""Graph configuration.

Settings the graph backend needs, read rather than hardcoded.

Stage-05's configuration system is frozen and carries no graph section, so these
settings are defined here and built from a mapping or from the environment using
the frozen readers. Nothing has a network default: a URI, a user and a database
must be supplied, and the password arrives as a :class:`Secret` whose value
never appears in a repr, a log line or an error message.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.config.coercion import as_int, as_str
from src.config.environment import EnvironmentReader
from src.config.secrets import Secret
from src.config.types import ConfigMapping

DEFAULT_BATCH_SIZE = 1000
DEFAULT_NAMESPACE = "odosian"


@dataclass(frozen=True, slots=True)
class Neo4jSettings:
    """Connection and write settings for the Neo4j backend."""

    uri: str
    user: str
    database: str
    password: Secret | None = field(default=None, repr=False)
    namespace: str = DEFAULT_NAMESPACE
    batch_size: int = DEFAULT_BATCH_SIZE

    @classmethod
    def from_mapping(cls, data: ConfigMapping, *, password: Secret | None = None) -> Neo4jSettings:
        """Build settings from a configuration section."""
        return cls(
            uri=as_str(data, "uri"),
            user=as_str(data, "user"),
            database=as_str(data, "database", default="neo4j"),
            password=password,
            namespace=as_str(data, "namespace", default=DEFAULT_NAMESPACE),
            batch_size=as_int(data, "batch_size", default=DEFAULT_BATCH_SIZE),
        )

    @classmethod
    def from_environment(
        cls,
        reader: EnvironmentReader,
        *,
        password: Secret | None = None,
    ) -> Neo4jSettings:
        """Build settings from prefixed environment variables."""
        return cls(
            uri=reader.require("NEO4J_URI"),
            user=reader.require("NEO4J_USER"),
            database=reader.get("NEO4J_DATABASE") or "neo4j",
            password=password,
            namespace=reader.get("NEO4J_NAMESPACE") or DEFAULT_NAMESPACE,
            batch_size=_positive_int(reader.get("NEO4J_BATCH_SIZE"), DEFAULT_BATCH_SIZE),
        )

    @property
    def has_password(self) -> bool:
        """Return whether a password was supplied, without revealing it."""
        return self.password is not None


def _positive_int(value: str | None, default: int) -> int:
    """Return a positive integer setting, falling back when unusable."""
    if value is None or not value.strip().isdigit():
        return default
    parsed = int(value.strip())
    return parsed if parsed > 0 else default
