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


class ThinkingLevel(StrEnum):
    """How much internal reasoning a model may spend before answering.

    Provider-neutral, and deliberately a coarse scale rather than a token count:
    a budget expressed in tokens means something different to every backend,
    while "as little as possible" and "as much as needed" travel.

    The setting exists because on reasoning models the internal reasoning is
    paid for out of the same output allowance as the answer. Left unbounded it
    can consume the whole allowance and truncate the reply, which is exactly
    what a measured Gemini call did before this setting existed.

    Leaving it unset means the provider's own default applies.
    """

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
