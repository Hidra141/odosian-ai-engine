"""Configuration loading.

Orchestrates the other modules of this package into one entry point.

Precedence, lowest to highest:

1. the base files in the config directory
2. their ``*.local.yaml`` counterparts, when present
3. mapped ``ODOSIAN_*`` environment variables

The result is validated before it is returned, and secrets are resolved last so
a malformed configuration fails before any credential is read.

Nothing is cached at module level: a caller loads the configuration once and
passes the result to the modules that need it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, final

from .environment import DEFAULT_ENV_PREFIX, EnvironmentReader
from .secrets import Secret, SecretsLoader
from .settings import EngineConfig
from .types import ConfigValue
from .validators import validate_config
from .yaml_loader import load_yaml_file, merge_mappings

DEFAULT_CONFIG_DIRNAME: Final[str] = "configs"
LOCAL_OVERRIDE_SUFFIX: Final[str] = ".local.yaml"
CONFIG_FILENAMES: Final[tuple[str, ...]] = (
    "engine.yaml",
    "model.yaml",
    "logging.yaml",
    "security.yaml",
)


@dataclass(frozen=True, slots=True)
class LoaderOptions:
    """Inputs that determine where configuration is read from."""

    root_dir: Path
    config_dir: Path
    dotenv_path: Path | None = None
    env_prefix: str = DEFAULT_ENV_PREFIX
    require_existing_paths: bool = False

    @classmethod
    def for_root(
        cls,
        root_dir: Path,
        *,
        config_dir: Path | None = None,
        dotenv_path: Path | None = None,
        require_existing_paths: bool = False,
    ) -> LoaderOptions:
        """Build options for a project root, defaulting to ``<root>/configs``."""
        resolved_root = root_dir.resolve()
        resolved_config = config_dir or resolved_root / DEFAULT_CONFIG_DIRNAME
        return cls(
            root_dir=resolved_root,
            config_dir=resolved_config.resolve(),
            dotenv_path=dotenv_path,
            require_existing_paths=require_existing_paths,
        )


@dataclass(frozen=True, slots=True)
class LoadedConfiguration:
    """A validated configuration together with its resolved secrets."""

    config: EngineConfig
    secrets: Mapping[str, Secret]
    sources: tuple[Path, ...]


@final
class ConfigLoader:
    """Assemble the engine configuration from files, environment and secrets."""

    def __init__(self, options: LoaderOptions, reader: EnvironmentReader | None = None) -> None:
        """Store the loader inputs. Nothing is read until :meth:`load` is called."""
        self._options = options
        self._reader = reader or EnvironmentReader.from_process(
            prefix=options.env_prefix,
            dotenv_path=options.dotenv_path,
        )

    def load(self) -> LoadedConfiguration:
        """Read, merge, validate and return the complete configuration."""
        sources = self._resolve_sources()
        data = self._read_files(sources)
        data = self._apply_env_overrides(data)
        config = EngineConfig.from_mapping(data, self._options.root_dir)
        result = validate_config(
            config,
            require_existing_paths=self._options.require_existing_paths,
        )
        result.raise_if_invalid()
        secrets = SecretsLoader(config.security, self._reader).load()
        return LoadedConfiguration(config=config, secrets=secrets, sources=sources)

    def _resolve_sources(self) -> tuple[Path, ...]:
        """Return the files to read, each base file followed by its local override."""
        sources: list[Path] = []
        for filename in CONFIG_FILENAMES:
            base = self._options.config_dir / filename
            sources.append(base)
            local = base.with_name(f"{base.stem}{LOCAL_OVERRIDE_SUFFIX}")
            if local.is_file():
                sources.append(local)
        return tuple(sources)

    def _read_files(self, sources: tuple[Path, ...]) -> dict[str, ConfigValue]:
        """Read every source file and merge them in order."""
        merged: dict[str, ConfigValue] = {}
        for path in sources:
            merged = merge_mappings(merged, load_yaml_file(path))
        return merged

    def _apply_env_overrides(self, data: Mapping[str, ConfigValue]) -> dict[str, ConfigValue]:
        """Overlay mapped environment variables onto the merged file data."""
        merged: dict[str, ConfigValue] = dict(data)
        for dotted_key, value in self._reader.overrides().items():
            merged = merge_mappings(merged, _nest(dotted_key, value))
        return merged


def _nest(dotted_key: str, value: ConfigValue) -> dict[str, ConfigValue]:
    """Expand ``a.b.c`` into ``{'a': {'b': {'c': value}}}``."""
    *prefix, leaf = dotted_key.split(".")
    nested: dict[str, ConfigValue] = {leaf: value}
    for part in reversed(prefix):
        nested = {part: nested}
    return nested


def load_configuration(
    root_dir: Path,
    *,
    config_dir: Path | None = None,
    dotenv_path: Path | None = None,
    require_existing_paths: bool = False,
) -> LoadedConfiguration:
    """Load the configuration for a project root using the default layout."""
    options = LoaderOptions.for_root(
        root_dir,
        config_dir=config_dir,
        dotenv_path=dotenv_path,
        require_existing_paths=require_existing_paths,
    )
    return ConfigLoader(options).load()
