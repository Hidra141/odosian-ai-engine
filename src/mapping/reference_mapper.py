"""Reference mapping.

Maps rule tags and references, normalising ATT&CK and CVE identifier syntax.

Identifier syntax is all this mapper reads. ``attack.t1059.001`` becomes the
identifier ``T1059.001`` because the Sigma tag convention writes technique
identifiers that way and case is not significant in them. **No ATT&CK object is
retrieved.** Nothing is learned about what T1059.001 is, what tactic it belongs
to, or whether it exists at all — the corpora that would answer those questions
are Stage-11's, and this layer never opens them.

A tactic tag such as ``attack.execution`` is recognised as a tactic reference by
its shape, but no ``TA`` identifier is produced for it. Turning a tactic *name*
into a tactic *identifier* requires the ATT&CK corpus, and inventing one here
would hand a later stage a fabricated identifier it would treat as authoritative.
The name is carried as the canonical value and the identifier is left empty.

Any tag that is not an identifier is a rule tag, which is its own canonical
form. That is an exact mapping, not a failure to map.
"""

from __future__ import annotations

import re
from typing import Final, final

from src.entities.models import Entity
from src.entities.types import EntityType

from .base_mapper import exact, normalized, unresolved
from .models import MappedEntity
from .types import CanonicalType, MappingMethod

_ATTACK_PREFIX: Final[str] = "attack."

_TECHNIQUE: Final[re.Pattern[str]] = re.compile(r"\AT(?P<number>\d{4})(?:\.(?P<sub>\d{3}))?\Z", re.I)
_TACTIC_ID: Final[re.Pattern[str]] = re.compile(r"\ATA(?P<number>\d{4})\Z", re.I)
_GROUP_ID: Final[re.Pattern[str]] = re.compile(r"\AG(?P<number>\d{4})\Z", re.I)
_SOFTWARE_ID: Final[re.Pattern[str]] = re.compile(r"\AS(?P<number>\d{4})\Z", re.I)
_CVE: Final[re.Pattern[str]] = re.compile(r"\ACVE-(?P<year>\d{4})-(?P<serial>\d{4,})\Z", re.I)
_URL: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*://\S+\Z")


@final
class ReferenceMapper:
    """Maps rule tags and references."""

    __slots__ = ()

    @property
    def name(self) -> str:
        """Return this mapper's identifier."""
        return "reference"

    @property
    def source_types(self) -> tuple[EntityType, ...]:
        """Return the extracted entity types this mapper handles."""
        return (EntityType.TAG, EntityType.REFERENCE)

    def map(self, entity: Entity) -> MappedEntity:
        """Return the canonical form of a tag or reference."""
        if entity.entity_type is EntityType.REFERENCE:
            return self._map_reference(entity)
        return self._map_tag(entity)

    def _map_reference(self, entity: Entity) -> MappedEntity:
        """Return a reference URL, or nothing when the value is not a URL."""
        value = entity.value.strip()
        if _URL.match(value):
            return exact(entity, CanonicalType.REFERENCE_URL, mapper=self.name)
        return unresolved(
            entity,
            mapper=self.name,
            note="reference is not a URL; citation form is not canonicalised",
            method=MappingMethod.SYNTAX_PATTERN,
        )

    def _map_tag(self, entity: Entity) -> MappedEntity:
        """Return an identifier reference when the tag carries one."""
        value = entity.value.strip()
        token = value[len(_ATTACK_PREFIX) :] if value.lower().startswith(_ATTACK_PREFIX) else value
        is_attack_tag = value.lower().startswith(_ATTACK_PREFIX)

        identified = self._identifier(entity, token)
        if identified is not None:
            return identified

        cve = _CVE.match(token)
        if cve is not None:
            canonical = f"CVE-{cve.group('year')}-{cve.group('serial')}"
            return self._reference(entity, CanonicalType.CVE_REFERENCE, canonical)

        if is_attack_tag and token:
            return normalized(
                entity,
                CanonicalType.ATTACK_TACTIC_REFERENCE,
                token.lower(),
                mapper=self.name,
                method=MappingMethod.SYNTAX_PATTERN,
                canonical_id=None,
            )
        return exact(entity, CanonicalType.RULE_TAG, mapper=self.name)

    def _identifier(self, entity: Entity, token: str) -> MappedEntity | None:
        """Return an ATT&CK reference when the token is an identifier."""
        technique = _TECHNIQUE.match(token)
        if technique is not None:
            number = technique.group("number")
            sub = technique.group("sub")
            canonical = f"T{number}.{sub}" if sub else f"T{number}"
            return self._reference(entity, CanonicalType.ATTACK_TECHNIQUE_REFERENCE, canonical)

        for pattern, canonical_type, letters in (
            (_TACTIC_ID, CanonicalType.ATTACK_TACTIC_REFERENCE, "TA"),
            (_GROUP_ID, CanonicalType.ATTACK_GROUP_REFERENCE, "G"),
            (_SOFTWARE_ID, CanonicalType.ATTACK_SOFTWARE_REFERENCE, "S"),
        ):
            match = pattern.match(token)
            if match is not None:
                return self._reference(entity, canonical_type, f"{letters}{match.group('number')}")
        return None

    def _reference(
        self,
        entity: Entity,
        canonical_type: CanonicalType,
        canonical: str,
    ) -> MappedEntity:
        """Build an identifier reference, exact when the value already matched."""
        if canonical == entity.value:
            return exact(entity, canonical_type, mapper=self.name, canonical_id=canonical)
        return normalized(
            entity,
            canonical_type,
            canonical,
            mapper=self.name,
            method=MappingMethod.SYNTAX_PATTERN,
            canonical_id=canonical,
        )
