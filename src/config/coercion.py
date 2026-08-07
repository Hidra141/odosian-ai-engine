"""Configuration value coercion.

Reads typed values out of a raw configuration mapping. Every helper raises a
configuration exception rather than returning a silently wrong value, so a
malformed file fails at load time instead of deep inside another module.

A key that is absent and a key whose value is ``null`` are treated the same way:
the supplied default is used, or :class:`MissingConfigKeyError` is raised.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final, TypeVar, cast

from .exceptions import InvalidConfigValueError, MissingConfigKeyError
from .types import ConfigMapping, ConfigValue

_EnumT = TypeVar("_EnumT", bound=StrEnum)

_TRUE_TOKENS: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_FALSE_TOKENS: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})


def get_section(data: ConfigMapping, name: str) -> ConfigMapping:
    """Return a nested mapping, raising when it is missing or not a mapping."""
    value = data.get(name)
    if value is None:
        raise MissingConfigKeyError(name)
    if not isinstance(value, Mapping):
        raise InvalidConfigValueError(name, value, "a mapping")
    return cast(ConfigMapping, value)


def _required(data: ConfigMapping, key: str) -> ConfigValue:
    """Return a value that must be present and non-null."""
    value = data.get(key)
    if value is None:
        raise MissingConfigKeyError(key)
    return value


def as_str(data: ConfigMapping, key: str, *, default: str | None = None) -> str:
    """Return a string value."""
    value = data.get(key)
    if value is None:
        if default is not None:
            return default
        raise MissingConfigKeyError(key)
    if not isinstance(value, str):
        raise InvalidConfigValueError(key, value, "a string")
    return value


def as_int(data: ConfigMapping, key: str, *, default: int | None = None) -> int:
    """Return an integer value, accepting the string form used by env overrides."""
    value = data.get(key)
    if value is None:
        if default is not None:
            return default
        raise MissingConfigKeyError(key)
    if isinstance(value, bool):
        raise InvalidConfigValueError(key, value, "an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError as error:
            raise InvalidConfigValueError(key, value, "an integer") from error
    raise InvalidConfigValueError(key, value, "an integer")


def as_float(data: ConfigMapping, key: str, *, default: float | None = None) -> float:
    """Return a float value, accepting the string form used by env overrides."""
    value = data.get(key)
    if value is None:
        if default is not None:
            return default
        raise MissingConfigKeyError(key)
    if isinstance(value, bool):
        raise InvalidConfigValueError(key, value, "a number")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError as error:
            raise InvalidConfigValueError(key, value, "a number") from error
    raise InvalidConfigValueError(key, value, "a number")


def as_bool(data: ConfigMapping, key: str, *, default: bool | None = None) -> bool:
    """Return a boolean value, accepting the string form used by env overrides."""
    value = data.get(key)
    if value is None:
        if default is not None:
            return default
        raise MissingConfigKeyError(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE_TOKENS:
            return True
        if token in _FALSE_TOKENS:
            return False
    raise InvalidConfigValueError(key, value, "a boolean")


def as_path(data: ConfigMapping, key: str, *, default: str | None = None) -> Path:
    """Return a filesystem path. Relative values are left unresolved."""
    return Path(as_str(data, key, default=default))


def as_optional_path(data: ConfigMapping, key: str) -> Path | None:
    """Return a filesystem path, or ``None`` when the key is unset or null."""
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidConfigValueError(key, value, "a string path or null")
    text = value.strip()
    return Path(text) if text else None


def as_str_tuple(data: ConfigMapping, key: str, *, default: tuple[str, ...] | None = None) -> tuple[str, ...]:
    """Return a tuple of strings from a YAML sequence or a comma-separated string."""
    value = data.get(key)
    if value is None:
        if default is not None:
            return default
        raise MissingConfigKeyError(key)
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, Sequence):
        items: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise InvalidConfigValueError(key, item, "a string")
            items.append(item)
        return tuple(items)
    raise InvalidConfigValueError(key, value, "a sequence of strings")


def as_enum(
    data: ConfigMapping,
    key: str,
    enum_type: type[_EnumT],
    *,
    default: _EnumT | None = None,
) -> _EnumT:
    """Return an enum member, matched case-insensitively against its value."""
    value = data.get(key)
    if value is None:
        if default is not None:
            return default
        raise MissingConfigKeyError(key)
    if not isinstance(value, str):
        raise InvalidConfigValueError(key, value, f"one of {_choices(enum_type)}")
    token = value.strip().lower()
    for member in enum_type:
        if member.value.lower() == token:
            return member
    raise InvalidConfigValueError(key, value, f"one of {_choices(enum_type)}")


def _choices(enum_type: type[StrEnum]) -> str:
    """Return the accepted values of an enum, formatted for an error message."""
    return ", ".join(member.value for member in enum_type)
