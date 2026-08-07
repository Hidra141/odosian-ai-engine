"""Logging configuration.

Turns :class:`LoggingSettings` into a :mod:`logging.config` dictionary and
applies it. Building the dictionary is pure, so it can be inspected or asserted
on without touching the process-wide logging state.
"""

from __future__ import annotations

import json
import logging
import logging.config
from typing import Any, Final

from .exceptions import InvalidConfigValueError
from .settings import LoggingSettings
from .types import LogFormat, LogOutput

_TEXT_FORMAT: Final[str] = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        """Return the record serialised as a JSON document."""
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def build_dict_config(settings: LoggingSettings) -> dict[str, Any]:
    """Return a :mod:`logging.config` dictionary for the given settings."""
    if settings.format is LogFormat.JSON:
        formatter: dict[str, Any] = {
            "()": f"{JsonFormatter.__module__}.{JsonFormatter.__qualname__}"
        }
    else:
        formatter = {"format": _TEXT_FORMAT}
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"default": formatter},
        "handlers": {"default": _build_handler(settings)},
        "root": {"level": settings.level.value, "handlers": ["default"]},
    }


def _build_handler(settings: LoggingSettings) -> dict[str, Any]:
    """Return the handler definition matching the configured output."""
    if settings.output is LogOutput.FILE:
        if settings.file_path is None:
            raise InvalidConfigValueError(
                "logging.file_path", None, "a path when output is 'file'"
            )
        return {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(settings.file_path),
            "maxBytes": settings.max_bytes,
            "backupCount": settings.backup_count,
            "encoding": "utf-8",
            "formatter": "default",
            "level": settings.level.value,
        }
    stream = "ext://sys.stderr" if settings.output is LogOutput.STDERR else "ext://sys.stdout"
    return {
        "class": "logging.StreamHandler",
        "stream": stream,
        "formatter": "default",
        "level": settings.level.value,
    }


def configure_logging(settings: LoggingSettings) -> None:
    """Apply the logging configuration to the process-wide logging system.

    Creates the parent directory of the log file when writing to disk.
    """
    if settings.output is LogOutput.FILE and settings.file_path is not None:
        settings.file_path.parent.mkdir(parents=True, exist_ok=True)
    logging.config.dictConfig(build_dict_config(settings))
