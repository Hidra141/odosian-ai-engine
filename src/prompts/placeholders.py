"""Placeholder scanning.

Placeholders take the ``{{NAME}}`` form, where ``NAME`` is upper case and may
contain digits and underscores, for example ``{{RULE}}`` or ``{{MITRE}}``.
Surrounding whitespace inside the braces is ignored, so ``{{ RULE }}`` names the
same variable.

Scanning is shared by the renderer and the validator, which is why it lives in
its own module rather than in either of them.
"""

from __future__ import annotations

import re
from typing import Final

ANY_PLACEHOLDER_PATTERN: Final[re.Pattern[str]] = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
VALID_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[A-Z][A-Z0-9_]*\Z")

_OPENING: Final[str] = "{{"
_CLOSING: Final[str] = "}}"


def find_placeholders(text: str) -> tuple[str, ...]:
    """Return every well-formed placeholder name, in order of first appearance."""
    names: list[str] = []
    for match in ANY_PLACEHOLDER_PATTERN.finditer(text):
        name = match.group(1).strip()
        if VALID_NAME_PATTERN.match(name) and name not in names:
            names.append(name)
    return tuple(names)


def find_malformed(text: str) -> tuple[str, ...]:
    """Return every placeholder-like fragment that is not a valid placeholder."""
    malformed: list[str] = []
    for match in ANY_PLACEHOLDER_PATTERN.finditer(text):
        if VALID_NAME_PATTERN.match(match.group(1).strip()):
            continue
        fragment = match.group(0)
        if fragment not in malformed:
            malformed.append(fragment)
    if text.count(_OPENING) != text.count(_CLOSING):
        malformed.append(f"unbalanced {_OPENING!r} and {_CLOSING!r}")
    return tuple(malformed)
