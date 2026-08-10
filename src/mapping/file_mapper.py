"""File mapping.

Maps filesystem objects to their canonical types, and canonicalises hash digests.

A hash is the one filesystem value with a canonical form worth deriving. Sysmon
writes ``SHA256=E3B0...`` while ECS writes the bare digest, and hex digests
appear in both cases. Splitting on the delimiter and lower-casing the digest is
structural: the digest is a hex number, and hex is case-insensitive by
definition, so nothing is lost.

The algorithm is taken from the label when one is present, and from the digest's
length when it is not. Length is not a guess — the three lengths recognised here
belong to exactly one common algorithm each. Any other length is left
unresolved rather than attributed to something.

A value carrying several digests at once, as Sysmon's multi-hash form does, is
left unresolved. Picking one of them would be a choice this layer has no basis
to make.
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Final, final

from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import TypeTable, map_by_type, normalized, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod

_TYPES: Final[TypeTable] = MappingProxyType(
    {
        EntityType.FILE_PATH: CanonicalType.FILE_PATH,
        EntityType.FILE_NAME: CanonicalType.FILE_NAME,
        EntityType.DIRECTORY: CanonicalType.DIRECTORY,
    }
)

_HASH_BY_LENGTH: Final[MappingProxyType[int, str]] = MappingProxyType(
    {32: "md5", 40: "sha1", 64: "sha256"}
)

_LABELLED_HASH: Final[re.Pattern[str]] = re.compile(
    r"\A\s*(?P<algorithm>[A-Za-z0-9_]+)\s*=\s*(?P<digest>[A-Fa-f0-9]+)\s*\Z"
)
_BARE_HASH: Final[re.Pattern[str]] = re.compile(r"\A\s*(?P<digest>[A-Fa-f0-9]+)\s*\Z")


@final
class FileMapper:
    """Maps file paths, names, directories and hashes."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "file"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (*_TYPES, EntityType.FILE_HASH)

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a filesystem object."""
        if entity.entity_type is EntityType.FILE_HASH:
            return self._map_hash(entity)
        return map_by_type(entity, _TYPES, mapper=self.name)

    def _map_hash(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a hash value."""
        value = entity.value
        if value.count("=") > 1 or "," in value:
            return unresolved(
                entity,
                mapper=self.name,
                note="value carries several digests; none chosen",
                canonical_type=CanonicalType.FILE_HASH,
                method=MappingMethod.AMBIGUOUS,
            )

        labelled = _LABELLED_HASH.match(value)
        if labelled is not None:
            return self._digest(
                entity,
                digest=labelled.group("digest"),
                algorithm=labelled.group("algorithm").lower(),
                method=MappingMethod.VALUE_SPLIT,
            )

        bare = _BARE_HASH.match(value)
        if bare is not None:
            digest = bare.group("digest")
            algorithm = _HASH_BY_LENGTH.get(len(digest))
            if algorithm is None:
                return unresolved(
                    entity,
                    mapper=self.name,
                    note=f"digest length {len(digest)} matches no known algorithm",
                    canonical_type=CanonicalType.FILE_HASH,
                    method=MappingMethod.SYNTAX_PATTERN,
                )
            return self._digest(
                entity,
                digest=digest,
                algorithm=algorithm,
                method=MappingMethod.SYNTAX_PATTERN,
            )

        return unresolved(
            entity,
            mapper=self.name,
            note="value is not a recognisable hash digest",
            canonical_type=CanonicalType.FILE_HASH,
            method=MappingMethod.SYNTAX_PATTERN,
        )

    def _digest(
        self,
        entity: Entity,
        *,
        digest: str,
        algorithm: str,
        method: MappingMethod,
    ) -> MappedEntity:
        """Build a mapped hash from a digest and its algorithm."""
        canonical = digest.lower()
        return normalized(
            entity,
            CanonicalType.FILE_HASH,
            canonical,
            mapper=self.name,
            method=method,
            canonical_id=canonical,
            attributes={"algorithm": algorithm, "digest_length": str(len(canonical))},
        )
