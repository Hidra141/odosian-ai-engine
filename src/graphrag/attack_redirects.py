"""ATT&CK identifier redirects.

Where a rule names a technique ATT&CK has since renumbered.

The corpus is a current ATT&CK snapshot; the rules that cite it are not. A rule
written against an earlier release names ``T1562.001``, and no node carries that
identifier any more, because ATT&CK revoked it in favour of ``T1685``. Without
this table such a reference reaches nothing: it is reported unresolved, which is
honest but wastes evidence the corpus does in fact hold.

What this module does **not** do is as important as what it does.

* It never rewrites the rule. The identifier the rule wrote stays the seed's
  ``value`` and stays in :attr:`~src.graphrag.models.RetrievalQuery.entity_ids`,
  which is what the lexical route asks the index with.
* It never manufactures a node. A redirect is followed only when the successor
  is a record the corpus already holds; when it is not, the reference stays
  unresolved and says so.
* It never reports a redirected reference as an ordinary resolved one. The seed
  carries :attr:`~src.graphrag.types.SeedStatus.REDIRECTED` and both
  identifiers, so every later stage can tell a reference the corpus holds from
  one it reached by following ATT&CK's own renumbering.

Every entry was verified against two independent authoritative sources that
agree on all thirteen: the ``revoked-by`` relationships in the ATT&CK 19.2 STIX
bundle, and the redirect ``attack.mitre.org`` serves for each revoked technique
URL. Nothing here was inferred from a name.

The table maps to a *tuple* of successors even though every authorised entry has
exactly one. ATT&CK does publish one-to-many revocations elsewhere, and a table
that could only express one successor would have to choose silently the first
time it met one. This one cannot: :func:`redirect_for` reports a many-successor
entry as ambiguous and seeds nothing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

ATTACK_REDIRECTS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "T1070.001": ("T1685.005",),
        "T1070.002": ("T1685.006",),
        "T1086": ("T1059.001",),
        "T1547.011": ("T1647",),
        "T1562": ("T1685",),
        "T1562.001": ("T1685",),
        "T1562.002": ("T1685.001",),
        "T1562.004": ("T1686",),
        "T1562.006": ("T1685",),
        "T1562.007": ("T1686.001",),
        "T1562.008": ("T1685.002",),
        "T1562.010": ("T1689",),
        "T1656": ("T1684.001",),
    }
)
"""The authorised deprecated-to-current ATT&CK technique mappings.

Keyed by the upper-case identifier, because that is the only spelling ATT&CK
publishes and the only one this table is prepared to answer for. Values are
tuples of successors; see the module docstring for why.
"""

_TECHNIQUE_ID: Final[re.Pattern[str]] = re.compile(r"^T\d{4}(?:\.\d{3})?$")
"""What an ATT&CK technique identifier looks like.

A lookup that does not match this shape is not a technique reference and is not
asked about, so a malformed string can never accidentally key the table.
"""


@dataclass(frozen=True, slots=True)
class AttackRedirect:
    """One deprecated identifier and the current identifier(s) that replaced it."""

    original_id: str
    """The identifier as the rule wrote it, preserved exactly."""

    successors: tuple[str, ...]
    """The current identifier(s) ATT&CK revoked it in favour of."""

    @property
    def is_one_to_one(self) -> bool:
        """Return whether exactly one successor replaced the original.

        Only a one-to-one redirect may be followed. Anything else is a choice
        this layer is not entitled to make on the rule's behalf.
        """
        return len(self.successors) == 1

    @property
    def successor(self) -> str:
        """Return the single successor.

        :raises ValueError: when the redirect is not one-to-one, so a caller
            that forgets to check :attr:`is_one_to_one` fails loudly rather than
            silently taking the first of several.
        """
        if not self.is_one_to_one:
            raise ValueError(
                f"{self.original_id} redirects to {len(self.successors)} identifiers; "
                "no single successor exists"
            )
        return self.successors[0]

    def __str__(self) -> str:
        """Return the redirect rendered for a report line."""
        return f"{self.original_id} -> {', '.join(self.successors)}"


def redirect_for(identifier: str) -> AttackRedirect | None:
    """Return the redirect for an identifier, or ``None`` when there is none.

    ``None`` is the answer for every identifier the corpus can resolve on its
    own, for every identifier ATT&CK has not revoked, and for every string that
    is not shaped like a technique reference at all. Only the thirteen
    authorised entries produce a redirect.
    """
    token = identifier.strip().upper()
    if not _TECHNIQUE_ID.match(token):
        return None
    successors = ATTACK_REDIRECTS.get(token)
    if successors is None:
        return None
    return AttackRedirect(original_id=identifier.strip(), successors=successors)
