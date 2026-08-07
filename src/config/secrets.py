"""Secrets loading.

Resolves the secrets declared in the security settings from the environment or
from an untracked secrets file. Secret values never come from the tracked
configuration files, and never appear in a traceback or a log record: they are
wrapped in :class:`Secret`, whose representation is redacted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import final

from .environment import EnvironmentReader
from .exceptions import MissingSecretError
from .settings import SecuritySettings
from .types import SecretsProvider
from .yaml_loader import load_yaml_file


@final
class Secret:
    """A secret value whose contents never appear in ``repr`` or ``str``."""

    __slots__ = ("_name", "_value")

    def __init__(self, name: str, value: str) -> None:
        """Wrap a secret value under its logical name."""
        self._name = name
        self._value = value

    @property
    def name(self) -> str:
        """Return the logical name of the secret."""
        return self._name

    def reveal(self) -> str:
        """Return the secret value. Call only where the value is actually used."""
        return self._value

    def __repr__(self) -> str:
        """Return a redacted representation."""
        return f"Secret(name={self._name!r}, value='***')"

    def __str__(self) -> str:
        """Return a redacted representation."""
        return "***"


@dataclass(frozen=True, slots=True)
class SecretsLoader:
    """Resolve every secret declared by the security settings."""

    settings: SecuritySettings
    reader: EnvironmentReader

    def load(self) -> Mapping[str, Secret]:
        """Return each required secret, raising when one cannot be resolved."""
        available = self._read_source()
        resolved: dict[str, Secret] = {}
        for name in self.settings.required_secrets:
            value = available.get(name)
            if value is None or not value.strip():
                raise MissingSecretError(name)
            resolved[name] = Secret(name, value)
        return MappingProxyType(resolved)

    def _read_source(self) -> Mapping[str, str]:
        """Return raw name-to-value pairs from the configured provider."""
        if self.settings.secrets_provider is SecretsProvider.FILE:
            return self._read_file()
        return self._read_environment()

    def _read_environment(self) -> Mapping[str, str]:
        """Return secret values sourced from prefixed environment variables."""
        values: dict[str, str] = {}
        for name in self.settings.required_secrets:
            value = self.reader.get(name)
            if value is not None:
                values[name] = value
        return values

    def _read_file(self) -> Mapping[str, str]:
        """Return secret values sourced from the configured secrets file."""
        path = self.settings.secrets_file
        if path is None:
            raise MissingSecretError("security.secrets_file")
        document = load_yaml_file(path)
        values: dict[str, str] = {}
        for name, value in document.items():
            if isinstance(value, str):
                values[name] = value
        return values
