"""Configuration types.

Type definitions describing configuration values and enumerated settings.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum

type ConfigScalar = str | int | float | bool | None
type ConfigValue = ConfigScalar | Sequence[ConfigValue] | Mapping[str, ConfigValue]
type ConfigMapping = Mapping[str, ConfigValue]
type MutableConfigMapping = dict[str, ConfigValue]


class Environment(StrEnum):
    """Deployment environment the engine is running in."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    """Severity threshold applied to emitted log records."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(StrEnum):
    """Serialisation format of emitted log records."""

    JSON = "json"
    TEXT = "text"


class LogOutput(StrEnum):
    """Destination of emitted log records."""

    STDOUT = "stdout"
    STDERR = "stderr"
    FILE = "file"


class SecretsProvider(StrEnum):
    """Source from which secret values are resolved."""

    ENVIRONMENT = "environment"
    FILE = "file"
