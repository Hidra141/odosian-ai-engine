r"""Identifier occurrence.

What it means for an identifier to appear in supplied material, stated once.

Both validation layers ask the same question — did the material actually carry
this identifier? — and they must not answer it differently. Stage-15 asks it of
the response it has just parsed; Stage-16 asks it of whatever reaches the
acceptance boundary. A result the one accepts and the other rejects on the same
evidence would mean the guarantee depended on which layer looked, so the rule
lives here, above both, and neither states it again.

It sits in ``core`` rather than in a shared utility package because the rule is
part of the reasoning contract: ``prompts/shared/safety.md`` already tells the
model that identifiers must be reproduced exactly as supplied, and this is that
sentence made checkable. ``src.validation`` imports ``src.core`` and never the
reverse, so placing it here is the direction the dependencies already run.

The matching is not a word-boundary match. ``\b`` treats the dot in
``T1059.001`` as a boundary, so ``\bT1059\b`` finds the first half of a
sub-technique and material naming one technique would appear to supply another.
An occurrence therefore counts only when no identifier character precedes it and
none follows, where a dot continues an identifier just when something
identifier-like follows the dot. A trailing dot is punctuation: material reading
``... T1059.001.`` at the end of a sentence still supplies ``T1059.001``.

Matching is exact and case-sensitive. ``T1059.001`` and ``t1059.001`` are not the
same identifier, and nothing here normalises whitespace — collapsing it could
join two identifiers into a third that was never supplied.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Final

_LEFT_BOUNDARY: Final[str] = r"(?<![A-Za-z0-9_.\-])"
"""No identifier character may precede the match.

The dot is included so ``001`` cannot be read out of ``T1059.001``.
"""

_RIGHT_BOUNDARY: Final[str] = r"(?![A-Za-z0-9_\-])(?!\.[A-Za-z0-9_])"
"""No identifier character may follow, and no dot that itself continues one.

Two lookaheads rather than one character class: a following dot disqualifies the
match only when the dot belongs to the identifier, which is exactly when
something identifier-like follows it.
"""


def occurs_as_identifier(identifier: str, text: str) -> bool:
    """Return whether an identifier occurs in text as a complete identifier.

    An empty identifier occurs nowhere. Plain containment would say otherwise,
    since every string contains the empty string.
    """
    return bool(identifier) and _token_pattern(identifier).search(text) is not None


@lru_cache(maxsize=512)
def _token_pattern(identifier: str) -> re.Pattern[str]:
    """Return the compiled boundary-anchored pattern matching one identifier."""
    return re.compile(_LEFT_BOUNDARY + re.escape(identifier) + _RIGHT_BOUNDARY)
