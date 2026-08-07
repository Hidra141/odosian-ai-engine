"""Configuration validation.

Consistency checks applied to the resolved configuration. Coercion already
guarantees that every value has the right type; these checks cover ranges and
cross-field rules that a type alone cannot express.

Every issue found is collected before reporting, so one load reports all
problems rather than only the first.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from .exceptions import ConfigValidationError
from .settings import (
    EngineConfig,
    EngineSettings,
    LoggingSettings,
    ModelSettings,
    PathSettings,
    SecuritySettings,
)
from .types import LogOutput, SecretsProvider

_MAX_TEMPERATURE = 2.0


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A single configuration problem, addressed by its dotted key."""

    key: str
    message: str

    def __str__(self) -> str:
        """Return the issue rendered as ``key: message``."""
        return f"{self.key}: {self.message}"


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Outcome of validating a configuration."""

    issues: tuple[ValidationIssue, ...]

    @property
    def is_valid(self) -> bool:
        """Return whether the configuration passed every check."""
        return not self.issues

    def raise_if_invalid(self) -> None:
        """Raise :class:`ConfigValidationError` when any issue was found."""
        if self.issues:
            raise ConfigValidationError([str(issue) for issue in self.issues])


def validate_engine(settings: EngineSettings) -> Iterator[ValidationIssue]:
    """Yield issues found in the engine section."""
    if not settings.name.strip():
        yield ValidationIssue("engine.name", "must not be empty")
    if settings.request_timeout_seconds <= 0:
        yield ValidationIssue("engine.request_timeout_seconds", "must be greater than zero")
    if settings.max_concurrent_requests < 1:
        yield ValidationIssue("engine.max_concurrent_requests", "must be at least 1")


def validate_model(settings: ModelSettings) -> Iterator[ValidationIssue]:
    """Yield issues found in the model section."""
    if not settings.provider.strip():
        yield ValidationIssue("model.provider", "must not be empty")
    if not settings.name.strip():
        yield ValidationIssue("model.name", "must not be empty")
    if not 0.0 <= settings.temperature <= _MAX_TEMPERATURE:
        yield ValidationIssue("model.temperature", f"must be between 0.0 and {_MAX_TEMPERATURE}")
    if not 0.0 < settings.top_p <= 1.0:
        yield ValidationIssue("model.top_p", "must be greater than 0.0 and at most 1.0")
    if settings.max_output_tokens <= 0:
        yield ValidationIssue("model.max_output_tokens", "must be greater than zero")
    if settings.timeout_seconds <= 0:
        yield ValidationIssue("model.timeout_seconds", "must be greater than zero")
    if settings.max_retries < 0:
        yield ValidationIssue("model.max_retries", "must not be negative")
    if settings.retry_backoff_seconds < 0:
        yield ValidationIssue("model.retry_backoff_seconds", "must not be negative")


def validate_logging(settings: LoggingSettings) -> Iterator[ValidationIssue]:
    """Yield issues found in the logging section."""
    if settings.output is LogOutput.FILE and settings.file_path is None:
        yield ValidationIssue("logging.file_path", "is required when output is 'file'")
    if settings.max_bytes <= 0:
        yield ValidationIssue("logging.max_bytes", "must be greater than zero")
    if settings.backup_count < 0:
        yield ValidationIssue("logging.backup_count", "must not be negative")


def validate_security(settings: SecuritySettings) -> Iterator[ValidationIssue]:
    """Yield issues found in the security section."""
    if settings.secrets_provider is SecretsProvider.FILE and settings.secrets_file is None:
        yield ValidationIssue("security.secrets_file", "is required when provider is 'file'")
    seen: set[str] = set()
    for name in settings.required_secrets:
        if not name.strip():
            yield ValidationIssue("security.required_secrets", "must not contain empty names")
        elif name in seen:
            yield ValidationIssue("security.required_secrets", f"contains a duplicate: {name}")
        seen.add(name)


def validate_paths(settings: PathSettings) -> Iterator[ValidationIssue]:
    """Yield issues for asset directories that do not exist on this machine."""
    for key, path in (
        ("paths.resources_dir", settings.resources_dir),
        ("paths.knowledge_dir", settings.knowledge_dir),
        ("paths.prompts_dir", settings.prompts_dir),
    ):
        if not path.is_dir():
            yield ValidationIssue(key, f"directory does not exist: {path}")


def validate_config(
    config: EngineConfig,
    *,
    require_existing_paths: bool = False,
) -> ValidationResult:
    """Run every check and collect the resulting issues.

    Directory existence is checked only when ``require_existing_paths`` is set,
    because it depends on the machine rather than on the configuration itself.
    """
    issues: list[ValidationIssue] = []
    issues.extend(validate_engine(config.engine))
    issues.extend(validate_model(config.model))
    issues.extend(validate_logging(config.logging))
    issues.extend(validate_security(config.security))
    if require_existing_paths:
        issues.extend(validate_paths(config.paths))
    return ValidationResult(tuple(issues))
