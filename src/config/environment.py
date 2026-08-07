"""Environment variable loading.

Reads prefixed environment variables and maps a fixed subset of them onto
dotted configuration keys, so any file-based setting can be overridden per
deployment without editing a tracked file.

The process environment is never mutated: values from a dotenv file are read
into a private mapping and real environment variables take precedence over it.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

from dotenv import dotenv_values

from .exceptions import ConfigFileNotFoundError, EnvironmentVariableError

DEFAULT_ENV_PREFIX: Final[str] = "ODOSIAN_"

ENV_TO_CONFIG_KEY: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ENVIRONMENT": "engine.environment",
        "REQUEST_TIMEOUT_SECONDS": "engine.request_timeout_seconds",
        "MAX_CONCURRENT_REQUESTS": "engine.max_concurrent_requests",
        "RESOURCES_DIR": "paths.resources_dir",
        "KNOWLEDGE_DIR": "paths.knowledge_dir",
        "PROMPTS_DIR": "paths.prompts_dir",
        "MODEL_PROVIDER": "model.provider",
        "MODEL_NAME": "model.name",
        "MODEL_TEMPERATURE": "model.temperature",
        "MODEL_TOP_P": "model.top_p",
        "MODEL_MAX_OUTPUT_TOKENS": "model.max_output_tokens",
        "MODEL_TIMEOUT_SECONDS": "model.timeout_seconds",
        "MODEL_MAX_RETRIES": "model.max_retries",
        "LOG_LEVEL": "logging.level",
        "LOG_FORMAT": "logging.format",
        "LOG_OUTPUT": "logging.output",
        "LOG_FILE_PATH": "logging.file_path",
        "SECRETS_PROVIDER": "security.secrets_provider",
        "SECRETS_FILE": "security.secrets_file",
    }
)


def read_dotenv(path: Path) -> Mapping[str, str]:
    """Read a dotenv file into a mapping without touching ``os.environ``."""
    if not path.is_file():
        raise ConfigFileNotFoundError(path)
    values = dotenv_values(path, encoding="utf-8")
    return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, slots=True)
class EnvironmentReader:
    """Read-only view over one set of prefixed environment variables."""

    source: Mapping[str, str]
    prefix: str = DEFAULT_ENV_PREFIX

    @classmethod
    def from_process(
        cls,
        *,
        prefix: str = DEFAULT_ENV_PREFIX,
        dotenv_path: Path | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> EnvironmentReader:
        """Build a reader from the process environment and an optional dotenv file.

        Real environment variables win over values read from the dotenv file.
        """
        values: dict[str, str] = {}
        if dotenv_path is not None:
            values.update(read_dotenv(dotenv_path))
        values.update(os.environ if environ is None else environ)
        return cls(source=MappingProxyType(values), prefix=prefix)

    def get(self, name: str) -> str | None:
        """Return the raw value of a prefixed variable, or ``None`` when unset."""
        return self.source.get(f"{self.prefix}{name}")

    def require(self, name: str) -> str:
        """Return a prefixed variable, raising when it is absent or blank."""
        value = self.get(name)
        if value is None or not value.strip():
            raise EnvironmentVariableError(f"{self.prefix}{name}", "value is missing or empty")
        return value

    def overrides(self) -> dict[str, str]:
        """Return dotted configuration keys for every mapped variable that is set.

        Values stay as strings; the coercion helpers convert them to their
        declared types alongside the values read from YAML.
        """
        result: dict[str, str] = {}
        for suffix, dotted_key in ENV_TO_CONFIG_KEY.items():
            value = self.get(suffix)
            if value is not None and value.strip():
                result[dotted_key] = value
        return result
