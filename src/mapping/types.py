"""Entity mapping types.

The canonical vocabulary, and the two axes that describe how a mapping was
reached.

A :class:`CanonicalType` names *what kind of thing a value is*, in a form that
does not depend on the rule format it came from. It still says nothing about
what the thing means: ``PROCESS_IMAGE`` records that a value is an image path,
not that the binary is signed, abused, or mapped to any technique. Establishing
meaning requires the knowledge corpora, which this layer never opens.
"""

from __future__ import annotations

from enum import StrEnum


class CanonicalType(StrEnum):
    """The canonical kind of a mapped value."""

    # Execution
    PROCESS = "process"
    PROCESS_IMAGE = "process_image"
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
    REGISTRY_VALUE_NAME = "registry_value_name"
    REGISTRY_VALUE_DATA = "registry_value_data"

    # Events
    EVENT_ID = "event_id"
    EVENT_CHANNEL = "event_channel"
    EVENT_PROVIDER = "event_provider"
    LINUX_AUDIT_EVENT = "linux_audit_event"

    # Network
    IP_ADDRESS = "ip_address"
    IP_NETWORK = "ip_network"
    NETWORK_PORT = "network_port"
    NETWORK_PROTOCOL = "network_protocol"
    DOMAIN_NAME = "domain_name"
    URL = "url"

    # Identity
    USER_ACCOUNT = "user_account"
    SECURITY_IDENTIFIER = "security_identifier"
    GROUP = "group"

    # Field categories
    PROCESS_IMAGE_FIELD = "process_image_field"
    PROCESS_NAME_FIELD = "process_name_field"
    COMMAND_LINE_FIELD = "command_line_field"
    FILE_FIELD = "file_field"
    HASH_FIELD = "hash_field"
    REGISTRY_FIELD = "registry_field"
    EVENT_FIELD = "event_field"
    NETWORK_FIELD = "network_field"
    IDENTITY_FIELD = "identity_field"
    UNKNOWN_FIELD = "unknown_field"
    FIELD_MODIFIER = "field_modifier"

    # References
    ATTACK_TECHNIQUE_REFERENCE = "attack_technique_reference"
    ATTACK_TACTIC_REFERENCE = "attack_tactic_reference"
    ATTACK_GROUP_REFERENCE = "attack_group_reference"
    ATTACK_SOFTWARE_REFERENCE = "attack_software_reference"
    CVE_REFERENCE = "cve_reference"
    RULE_TAG = "rule_tag"
    REFERENCE_URL = "reference_url"

    # Rule metadata
    AUTHOR = "author"
    SEVERITY_LEVEL = "severity_level"
    RULE_STATUS = "rule_status"
    LOG_PRODUCT = "log_product"
    LOG_CATEGORY = "log_category"
    LOG_SERVICE = "log_service"
    LOG_INDEX = "log_index"
    TIMEFRAME = "timeframe"

    # Fallback
    UNKNOWN = "unknown"


class MappingStatus(StrEnum):
    """How firmly a canonical form was established."""

    EXACT = "exact"
    """The extracted value is already canonical; only its type was assigned."""

    NORMALIZED = "normalized"
    """A defined structural rule reshaped the value, such as case or hive form."""

    ALIAS = "alias"
    """A known alias table resolved the value or field to its canonical form."""

    UNRESOLVED = "unresolved"
    """No canonical form could be established without guessing."""

    @property
    def is_resolved(self) -> bool:
        """Return whether a canonical form was established."""
        return self is not MappingStatus.UNRESOLVED

    @property
    def confidence(self) -> float:
        """Return the certainty of the mapping.

        Every mapping this layer performs is deterministic: a table matched or
        it did not, a pattern matched or it did not. There is no middle ground,
        so a resolved mapping is fully certain and an unresolved one carries no
        certainty at all. The field exists because later stages will establish
        mappings by means that are not deterministic.
        """
        return 1.0 if self.is_resolved else 0.0


class MappingMethod(StrEnum):
    """The mechanism that produced a mapping."""

    DIRECT_TYPE = "direct_type"
    """The canonical type follows from the extracted type; the value is untouched."""

    ALIAS_TABLE = "alias_table"
    """A literal alias table was consulted."""

    SYNTAX_PATTERN = "syntax_pattern"
    """The value's own syntax determined the mapping."""

    CASE_NORMALIZATION = "case_normalization"
    """Only the case of the value changed."""

    ENUM_CONVERSION = "enum_conversion"
    """A value from a closed vocabulary was converted to its canonical member."""

    VALUE_SPLIT = "value_split"
    """A compound value was separated along a structural delimiter."""

    AMBIGUOUS = "ambiguous"
    """More than one canonical form applied, so none was chosen."""

    NONE = "none"
    """No mapping was attempted or none applied."""
