"""Entity extraction types.

The vocabulary of what can be extracted, and where it was found.

An :class:`EntityType` records the *kind of slot a value occupied*, not what the
value means. ``EXECUTABLE`` says the value sat in a field that holds executables;
it does not say the value is a real binary, that it is malicious, or that it
maps to any technique. Assigning meaning is Stage-10's work.
"""

from __future__ import annotations

from enum import StrEnum


class RuleSection(StrEnum):
    """The part of a parsed rule an entity was found in."""

    METADATA = "metadata"
    LOG_SOURCE = "log_source"
    DETECTION = "detection"
    CONDITION = "condition"
    TAGS = "tags"
    REFERENCES = "references"


class EntityType(StrEnum):
    """The kind of slot an extracted value occupied."""

    # Execution
    PROCESS = "process"
    EXECUTABLE = "executable"
    COMMAND_LINE = "command_line"
    COMMAND_ARGUMENT = "command_argument"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"

    # Filesystem
    FILE_PATH = "file_path"
    FILE_NAME = "file_name"
    DIRECTORY = "directory"
    FILE_HASH = "file_hash"

    # Registry
    REGISTRY_KEY = "registry_key"
    REGISTRY_VALUE = "registry_value"
    REGISTRY_DATA = "registry_data"

    # Events
    WINDOWS_EVENT_ID = "windows_event_id"
    WINDOWS_EVENT_CHANNEL = "windows_event_channel"
    WINDOWS_EVENT_PROVIDER = "windows_event_provider"
    LINUX_EVENT = "linux_event"

    # Network
    IP_ADDRESS = "ip_address"
    NETWORK_PORT = "network_port"
    NETWORK_PROTOCOL = "network_protocol"
    DNS_NAME = "dns_name"
    URL = "url"

    # Identity
    USER = "user"
    GROUP = "group"

    # Schema
    FIELD = "field"
    FIELD_MODIFIER = "field_modifier"

    # Rule metadata
    TAG = "tag"
    REFERENCE = "reference"
    AUTHOR = "author"
    SEVERITY = "severity"
    STATUS = "status"
    PRODUCT = "product"
    CATEGORY = "category"
    LOG_SOURCE_SERVICE = "log_source_service"
    LOG_INDEX = "log_index"
    TIMEFRAME = "timeframe"


DIRECT_EXTRACTION_CONFIDENCE: float = 1.0
"""Confidence carried by every entity this stage produces.

Extraction is direct: a value was read out of a field or matched a literal
shape. Nothing is inferred, so nothing is uncertain. The field exists for
downstream stages that will produce entities by less certain means.
"""
