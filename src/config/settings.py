"""Runtime settings.

Immutable dataclasses describing the resolved configuration of the engine.
Every section knows how to build itself from a raw configuration mapping; no
section reads the environment or the filesystem on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .coercion import (
    as_enum,
    as_float,
    as_int,
    as_optional_path,
    as_path,
    as_str,
    as_str_tuple,
    get_section,
)
from .types import (
    ConfigMapping,
    Environment,
    LogFormat,
    LogLevel,
    LogOutput,
    SecretsProvider,
)


def _resolve(path: Path, root_dir: Path) -> Path:
    """Return an absolute path, resolving relative values against ``root_dir``."""
    return path if path.is_absolute() else (root_dir / path).resolve()


@dataclass(frozen=True, slots=True)
class EngineSettings:
    """Identity and execution limits of the engine."""

    name: str
    environment: Environment
    request_timeout_seconds: int
    max_concurrent_requests: int

    @classmethod
    def from_mapping(cls, data: ConfigMapping) -> EngineSettings:
        """Build engine settings from the ``engine`` section."""
        section = get_section(data, "engine")
        return cls(
            name=as_str(section, "name"),
            environment=as_enum(section, "environment", Environment),
            request_timeout_seconds=as_int(section, "request_timeout_seconds", default=60),
            max_concurrent_requests=as_int(section, "max_concurrent_requests", default=4),
        )


@dataclass(frozen=True, slots=True)
class PathSettings:
    """Filesystem locations of the engine's non-code assets."""

    resources_dir: Path
    knowledge_dir: Path
    prompts_dir: Path

    @classmethod
    def from_mapping(cls, data: ConfigMapping, root_dir: Path) -> PathSettings:
        """Build path settings, resolving relative entries against ``root_dir``."""
        section = get_section(data, "paths")
        return cls(
            resources_dir=_resolve(as_path(section, "resources_dir"), root_dir),
            knowledge_dir=_resolve(as_path(section, "knowledge_dir"), root_dir),
            prompts_dir=_resolve(as_path(section, "prompts_dir"), root_dir),
        )


@dataclass(frozen=True, slots=True)
class ModelSettings:
    """Parameters describing which language model to call and how."""

    provider: str
    name: str
    temperature: float
    top_p: float
    max_output_tokens: int
    timeout_seconds: int
    max_retries: int
    retry_backoff_seconds: float

    @classmethod
    def from_mapping(cls, data: ConfigMapping) -> ModelSettings:
        """Build model settings from the ``model`` section."""
        section = get_section(data, "model")
        return cls(
            provider=as_str(section, "provider"),
            name=as_str(section, "name"),
            temperature=as_float(section, "temperature", default=0.2),
            top_p=as_float(section, "top_p", default=0.95),
            max_output_tokens=as_int(section, "max_output_tokens", default=4096),
            timeout_seconds=as_int(section, "timeout_seconds", default=60),
            max_retries=as_int(section, "max_retries", default=3),
            retry_backoff_seconds=as_float(section, "retry_backoff_seconds", default=1.0),
        )


@dataclass(frozen=True, slots=True)
class LoggingSettings:
    """Where log records go, at which severity, in which format."""

    level: LogLevel
    format: LogFormat
    output: LogOutput
    file_path: Path | None
    max_bytes: int
    backup_count: int

    @classmethod
    def from_mapping(cls, data: ConfigMapping, root_dir: Path) -> LoggingSettings:
        """Build logging settings from the ``logging`` section."""
        section = get_section(data, "logging")
        file_path = as_optional_path(section, "file_path")
        return cls(
            level=as_enum(section, "level", LogLevel, default=LogLevel.INFO),
            format=as_enum(section, "format", LogFormat, default=LogFormat.JSON),
            output=as_enum(section, "output", LogOutput, default=LogOutput.STDOUT),
            file_path=None if file_path is None else _resolve(file_path, root_dir),
            max_bytes=as_int(section, "max_bytes", default=10_485_760),
            backup_count=as_int(section, "backup_count", default=5),
        )


@dataclass(frozen=True, slots=True)
class SecuritySettings:
    """Which secrets the engine needs and where they are resolved from."""

    secrets_provider: SecretsProvider
    secrets_file: Path | None
    required_secrets: tuple[str, ...]

    @classmethod
    def from_mapping(cls, data: ConfigMapping, root_dir: Path) -> SecuritySettings:
        """Build security settings from the ``security`` section."""
        section = get_section(data, "security")
        secrets_file = as_optional_path(section, "secrets_file")
        return cls(
            secrets_provider=as_enum(
                section, "secrets_provider", SecretsProvider, default=SecretsProvider.ENVIRONMENT
            ),
            secrets_file=None if secrets_file is None else _resolve(secrets_file, root_dir),
            required_secrets=as_str_tuple(section, "required_secrets", default=()),
        )


@dataclass(frozen=True, slots=True)
class EngineConfig:
    """The fully resolved configuration of the AI engine."""

    engine: EngineSettings
    paths: PathSettings
    model: ModelSettings
    logging: LoggingSettings
    security: SecuritySettings

    @classmethod
    def from_mapping(cls, data: ConfigMapping, root_dir: Path) -> EngineConfig:
        """Build the complete configuration from a merged mapping."""
        return cls(
            engine=EngineSettings.from_mapping(data),
            paths=PathSettings.from_mapping(data, root_dir),
            model=ModelSettings.from_mapping(data),
            logging=LoggingSettings.from_mapping(data, root_dir),
            security=SecuritySettings.from_mapping(data, root_dir),
        )
