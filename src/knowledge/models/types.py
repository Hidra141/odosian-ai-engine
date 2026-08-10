"""Knowledge vocabulary.

The five sources, the kinds of reference that appear in them, and the outcome
of trying to resolve one.

Source names are not uniform in the corpus: records carry ``elastic-rules`` and
``gtfobins-lolbas`` in ``metadata.source`` while the directories are ``elastic``
and ``lolbas``. :meth:`KnowledgeSource.from_value` maps the known spellings onto
one member. It is a table of observed names, not a guess: a spelling the table
does not list returns ``None`` rather than a nearest match.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

type RawMetadata = Mapping[str, object]


class KnowledgeSource(StrEnum):
    """One of the five approved knowledge datasets."""

    MITRE = "mitre"
    SIGMA = "sigma"
    ELASTIC = "elastic"
    LOLBAS = "lolbas"
    ECS = "ecs"

    @classmethod
    def from_value(cls, value: object) -> KnowledgeSource | None:
        """Return the source a name denotes, or ``None`` when it is unknown."""
        if not isinstance(value, str):
            return None
        return _SOURCE_ALIASES.get(value.strip().lower())


_SOURCE_ALIASES: Final[Mapping[str, KnowledgeSource]] = MappingProxyType(
    {
        "mitre": KnowledgeSource.MITRE,
        "sigma": KnowledgeSource.SIGMA,
        "elastic": KnowledgeSource.ELASTIC,
        "elastic-rules": KnowledgeSource.ELASTIC,
        "lolbas": KnowledgeSource.LOLBAS,
        "gtfobins": KnowledgeSource.LOLBAS,
        "gtfobins-lolbas": KnowledgeSource.LOLBAS,
        "ecs": KnowledgeSource.ECS,
    }
)


class ReferenceKind(StrEnum):
    """The kind of thing a reference points at."""

    ATTACK_TECHNIQUE = "attack_technique"
    ATTACK_TACTIC = "attack_tactic"
    ATTACK_GROUP = "attack_group"
    ATTACK_SOFTWARE = "attack_software"
    ATTACK_MITIGATION = "attack_mitigation"
    ATTACK_DATA_SOURCE = "attack_data_source"
    CVE = "cve"
    ECS_FIELD = "ecs_field"
    SIGMA_RULE = "sigma_rule"
    ELASTIC_RULE = "elastic_rule"
    UNKNOWN = "unknown"


class ResolutionStatus(StrEnum):
    """The outcome of resolving a reference against the corpus."""

    RESOLVED = "resolved"
    """Exactly one record answers to the reference."""

    UNRESOLVED = "unresolved"
    """No record answers to it. The reference is preserved as written."""

    AMBIGUOUS = "ambiguous"
    """More than one record answers to it, and none was chosen."""

    @property
    def is_resolved(self) -> bool:
        """Return whether a single target was established."""
        return self is ResolutionStatus.RESOLVED
