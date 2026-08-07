"""Configuration layer.

Centralised loading of YAML configuration, environment overrides, secrets and
runtime settings. Every other module receives a resolved
:class:`~src.config.settings.EngineConfig` rather than reading files or the
environment for itself.

Typical use from the engine entry point::

    loaded = load_configuration(root_dir)
    configure_logging(loaded.config.logging)
"""

from __future__ import annotations

from .coercion import (
    as_bool,
    as_enum,
    as_float,
    as_int,
    as_optional_path,
    as_path,
    as_str,
    as_str_tuple,
    get_section,
)
from .config_loader import (
    CONFIG_FILENAMES,
    DEFAULT_CONFIG_DIRNAME,
    LOCAL_OVERRIDE_SUFFIX,
    ConfigLoader,
    LoadedConfiguration,
    LoaderOptions,
    load_configuration,
)
from .environment import (
    DEFAULT_ENV_PREFIX,
    ENV_TO_CONFIG_KEY,
    EnvironmentReader,
    read_dotenv,
)
from .exceptions import (
    ConfigError,
    ConfigFileNotFoundError,
    ConfigParseError,
    ConfigValidationError,
    EnvironmentVariableError,
    InvalidConfigValueError,
    MissingConfigKeyError,
    MissingSecretError,
)
from .logging_config import JsonFormatter, build_dict_config, configure_logging
from .secrets import Secret, SecretsLoader
from .settings import (
    EngineConfig,
    EngineSettings,
    LoggingSettings,
    ModelSettings,
    PathSettings,
    SecuritySettings,
)
from .types import (
    ConfigMapping,
    ConfigScalar,
    ConfigValue,
    Environment,
    LogFormat,
    LogLevel,
    LogOutput,
    MutableConfigMapping,
    SecretsProvider,
)
from .validators import (
    ValidationIssue,
    ValidationResult,
    validate_config,
    validate_engine,
    validate_logging,
    validate_model,
    validate_paths,
    validate_security,
)
from .yaml_loader import load_yaml_file, load_yaml_files, merge_mappings

__all__ = [
    "CONFIG_FILENAMES",
    "DEFAULT_CONFIG_DIRNAME",
    "DEFAULT_ENV_PREFIX",
    "ENV_TO_CONFIG_KEY",
    "LOCAL_OVERRIDE_SUFFIX",
    "ConfigError",
    "ConfigFileNotFoundError",
    "ConfigLoader",
    "ConfigMapping",
    "ConfigParseError",
    "ConfigScalar",
    "ConfigValidationError",
    "ConfigValue",
    "EngineConfig",
    "EngineSettings",
    "Environment",
    "EnvironmentReader",
    "EnvironmentVariableError",
    "InvalidConfigValueError",
    "JsonFormatter",
    "LoadedConfiguration",
    "LoaderOptions",
    "LogFormat",
    "LogLevel",
    "LogOutput",
    "LoggingSettings",
    "MissingConfigKeyError",
    "MissingSecretError",
    "ModelSettings",
    "MutableConfigMapping",
    "PathSettings",
    "Secret",
    "SecretsLoader",
    "SecretsProvider",
    "SecuritySettings",
    "ValidationIssue",
    "ValidationResult",
    "as_bool",
    "as_enum",
    "as_float",
    "as_int",
    "as_optional_path",
    "as_path",
    "as_str",
    "as_str_tuple",
    "build_dict_config",
    "configure_logging",
    "get_section",
    "load_configuration",
    "load_yaml_file",
    "load_yaml_files",
    "merge_mappings",
    "read_dotenv",
    "validate_config",
    "validate_engine",
    "validate_logging",
    "validate_model",
    "validate_paths",
    "validate_security",
]
