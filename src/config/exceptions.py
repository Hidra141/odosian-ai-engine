"""Configuration exceptions.

Error types raised while reading, resolving or validating configuration.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path


class ConfigError(Exception):
    """Base class for every configuration failure."""


class ConfigFileNotFoundError(ConfigError):
    """Raised when a required configuration file is absent."""

    def __init__(self, path: Path) -> None:
        """Record the path that could not be read."""
        super().__init__(f"Configuration file not found: {path}")
        self.path = path


class ConfigParseError(ConfigError):
    """Raised when a configuration file cannot be parsed."""

    def __init__(self, path: Path, reason: str) -> None:
        """Record the offending file and the underlying parser message."""
        super().__init__(f"Failed to parse configuration file {path}: {reason}")
        self.path = path
        self.reason = reason


class MissingConfigKeyError(ConfigError):
    """Raised when a required configuration key is absent."""

    def __init__(self, key: str) -> None:
        """Record the dotted key that was expected."""
        super().__init__(f"Missing required configuration key: {key}")
        self.key = key


class InvalidConfigValueError(ConfigError):
    """Raised when a configuration value has an unusable type or range."""

    def __init__(self, key: str, value: object, expected: str) -> None:
        """Record the key, the rejected value and what was expected instead."""
        super().__init__(
            f"Invalid value for configuration key {key!r}: expected {expected}, got {value!r}"
        )
        self.key = key
        self.value = value
        self.expected = expected


class ConfigValidationError(ConfigError):
    """Raised when the assembled configuration fails validation."""

    def __init__(self, messages: Sequence[str]) -> None:
        """Record every validation message produced by the validators."""
        super().__init__("Configuration validation failed: " + "; ".join(messages))
        self.messages = tuple(messages)


class MissingSecretError(ConfigError):
    """Raised when a declared secret cannot be resolved from its provider."""

    def __init__(self, name: str) -> None:
        """Record the logical name of the secret that is unavailable."""
        super().__init__(f"Required secret is not available: {name}")
        self.name = name


class EnvironmentVariableError(ConfigError):
    """Raised when an environment variable holds an unusable value."""

    def __init__(self, name: str, reason: str) -> None:
        """Record the variable name and why its value was rejected."""
        super().__init__(f"Invalid environment variable {name}: {reason}")
        self.name = name
        self.reason = reason
