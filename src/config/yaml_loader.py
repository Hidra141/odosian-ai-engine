"""YAML configuration loading.

Reads YAML documents from disk and merges them into a single mapping.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import cast

import yaml

from .exceptions import ConfigFileNotFoundError, ConfigParseError
from .types import ConfigMapping, ConfigValue


def load_yaml_file(path: Path) -> ConfigMapping:
    """Read one YAML document and return its top-level mapping.

    An empty document yields an empty mapping.
    """
    if not path.is_file():
        raise ConfigFileNotFoundError(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ConfigParseError(path, str(error)) from error
    except OSError as error:
        raise ConfigParseError(path, str(error)) from error
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ConfigParseError(path, "top-level document must be a mapping")
    return cast(ConfigMapping, raw)


def merge_mappings(base: ConfigMapping, override: ConfigMapping) -> dict[str, ConfigValue]:
    """Recursively merge ``override`` on top of ``base``.

    Nested mappings are merged key by key; every other value is replaced.
    """
    merged: dict[str, ConfigValue] = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            merged[key] = merge_mappings(cast(ConfigMapping, current), cast(ConfigMapping, value))
        else:
            merged[key] = value
    return merged


def load_yaml_files(paths: Iterable[Path]) -> dict[str, ConfigValue]:
    """Load several YAML documents and merge them in the order given."""
    merged: dict[str, ConfigValue] = {}
    for path in paths:
        merged = merge_mappings(merged, load_yaml_file(path))
    return merged
