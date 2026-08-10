"""Field mapping.

Maps referenced field names to a canonical field category, and carries Sigma
modifiers alongside them.

The alias table is a table of *names*, not a schema. It records that several
spellings across Windows telemetry and ECS occupy the same role; it does not
define those fields, validate them, or resolve them against ECS. A field the
table does not list is left unresolved rather than assigned a plausible
category.

Some names genuinely belong to more than one category. ``Source`` is a Windows
event provider field and also the root of the ECS ``source.*`` network group,
and nothing about the name alone decides which. Those entries hold several
candidates and produce an unresolved mapping, which a caller may escalate to an
error by mapping in strict mode.

Modifiers are recovered from the original field key, so a mapping for ``Image``
still records that the rule wrote ``Image|endswith``.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, final

from src.entities.base_extractor import split_field
from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import AliasTable, aliased, exact, resolve_alias, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod

_FIELDS: Final[AliasTable] = MappingProxyType(
    {
        # Process image
        "image": (CanonicalType.PROCESS_IMAGE_FIELD,),
        "parentimage": (CanonicalType.PROCESS_IMAGE_FIELD,),
        "newprocessname": (CanonicalType.PROCESS_IMAGE_FIELD,),
        "parentprocessname": (CanonicalType.PROCESS_IMAGE_FIELD,),
        "originalfilename": (CanonicalType.PROCESS_IMAGE_FIELD,),
        "imagepath": (CanonicalType.PROCESS_IMAGE_FIELD,),
        "process.executable": (CanonicalType.PROCESS_IMAGE_FIELD,),
        "process.parent.executable": (CanonicalType.PROCESS_IMAGE_FIELD,),
        # Process name
        "process.name": (CanonicalType.PROCESS_NAME_FIELD,),
        "process.parent.name": (CanonicalType.PROCESS_NAME_FIELD,),
        # Command line
        "commandline": (CanonicalType.COMMAND_LINE_FIELD,),
        "parentcommandline": (CanonicalType.COMMAND_LINE_FIELD,),
        "processcommandline": (CanonicalType.COMMAND_LINE_FIELD,),
        "scriptblocktext": (CanonicalType.COMMAND_LINE_FIELD,),
        "process.command_line": (CanonicalType.COMMAND_LINE_FIELD,),
        "process.parent.command_line": (CanonicalType.COMMAND_LINE_FIELD,),
        "process.args": (CanonicalType.COMMAND_LINE_FIELD,),
        # File
        "targetfilename": (CanonicalType.FILE_FIELD,),
        "sourcefilename": (CanonicalType.FILE_FIELD,),
        "filename": (CanonicalType.FILE_FIELD,),
        "targetdirectory": (CanonicalType.FILE_FIELD,),
        "currentdirectory": (CanonicalType.FILE_FIELD,),
        "file.path": (CanonicalType.FILE_FIELD,),
        "file.name": (CanonicalType.FILE_FIELD,),
        "file.directory": (CanonicalType.FILE_FIELD,),
        # Hash
        "hashes": (CanonicalType.HASH_FIELD,),
        "imphash": (CanonicalType.HASH_FIELD,),
        "md5": (CanonicalType.HASH_FIELD,),
        "sha1": (CanonicalType.HASH_FIELD,),
        "sha256": (CanonicalType.HASH_FIELD,),
        "file.hash.md5": (CanonicalType.HASH_FIELD,),
        "file.hash.sha1": (CanonicalType.HASH_FIELD,),
        "file.hash.sha256": (CanonicalType.HASH_FIELD,),
        # Registry
        "targetobject": (CanonicalType.REGISTRY_FIELD,),
        "objectname": (CanonicalType.REGISTRY_FIELD,),
        "valuename": (CanonicalType.REGISTRY_FIELD,),
        "details": (CanonicalType.REGISTRY_FIELD,),
        "registry.path": (CanonicalType.REGISTRY_FIELD,),
        "registry.key": (CanonicalType.REGISTRY_FIELD,),
        "registry.value": (CanonicalType.REGISTRY_FIELD,),
        # Event
        "eventid": (CanonicalType.EVENT_FIELD,),
        "event.code": (CanonicalType.EVENT_FIELD,),
        "winlog.event_id": (CanonicalType.EVENT_FIELD,),
        "channel": (CanonicalType.EVENT_FIELD,),
        "logname": (CanonicalType.EVENT_FIELD,),
        "winlog.channel": (CanonicalType.EVENT_FIELD,),
        "provider_name": (CanonicalType.EVENT_FIELD,),
        "winlog.provider_name": (CanonicalType.EVENT_FIELD,),
        # Network
        "destinationip": (CanonicalType.NETWORK_FIELD,),
        "sourceip": (CanonicalType.NETWORK_FIELD,),
        "destinationport": (CanonicalType.NETWORK_FIELD,),
        "sourceport": (CanonicalType.NETWORK_FIELD,),
        "destinationhostname": (CanonicalType.NETWORK_FIELD,),
        "queryname": (CanonicalType.NETWORK_FIELD,),
        "protocol": (CanonicalType.NETWORK_FIELD,),
        "destination.ip": (CanonicalType.NETWORK_FIELD,),
        "source.ip": (CanonicalType.NETWORK_FIELD,),
        "destination.port": (CanonicalType.NETWORK_FIELD,),
        "source.port": (CanonicalType.NETWORK_FIELD,),
        "dns.question.name": (CanonicalType.NETWORK_FIELD,),
        "url.original": (CanonicalType.NETWORK_FIELD,),
        "network.protocol": (CanonicalType.NETWORK_FIELD,),
        # Identity
        "user": (CanonicalType.IDENTITY_FIELD,),
        "username": (CanonicalType.IDENTITY_FIELD,),
        "subjectusername": (CanonicalType.IDENTITY_FIELD,),
        "targetusername": (CanonicalType.IDENTITY_FIELD,),
        "targetgroupname": (CanonicalType.IDENTITY_FIELD,),
        "user.name": (CanonicalType.IDENTITY_FIELD,),
        "group.name": (CanonicalType.IDENTITY_FIELD,),
        # Names that legitimately belong to more than one category
        "source": (CanonicalType.EVENT_FIELD, CanonicalType.NETWORK_FIELD),
        "type": (CanonicalType.EVENT_FIELD, CanonicalType.UNKNOWN_FIELD),
        "service": (CanonicalType.PROCESS_NAME_FIELD, CanonicalType.EVENT_FIELD),
    }
)


@final
class FieldMapper:
    """Maps field names to canonical field categories, and their modifiers."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "field"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (EntityType.FIELD, EntityType.FIELD_MODIFIER)

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a field reference."""
        if entity.entity_type is EntityType.FIELD_MODIFIER:
            return exact(entity, CanonicalType.FIELD_MODIFIER, mapper=self.name)

        base, modifiers = split_field(entity.source_field or entity.value)
        field_name = base or entity.value
        candidates = resolve_alias(_FIELDS, field_name)

        if len(candidates) == 1:
            return aliased(
                entity,
                candidates[0],
                mapper=self.name,
                canonical_value=field_name,
                canonical_field=field_name,
                modifiers=modifiers,
            )
        if len(candidates) > 1:
            names = ", ".join(item.value for item in candidates)
            return unresolved(
                entity,
                mapper=self.name,
                note=f"field name applies to several categories: {names}",
                canonical_type=CanonicalType.UNKNOWN_FIELD,
                method=MappingMethod.AMBIGUOUS,
                canonical_field=field_name,
                modifiers=modifiers,
            )
        return unresolved(
            entity,
            mapper=self.name,
            note="field name is not in the alias table",
            canonical_type=CanonicalType.UNKNOWN_FIELD,
            method=MappingMethod.ALIAS_TABLE,
            canonical_field=field_name,
            modifiers=modifiers,
        )
