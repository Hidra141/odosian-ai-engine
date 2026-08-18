"""Extractor contract and shared machinery.

Defines the interface an extractor satisfies, the traversal that turns a parsed
rule into flat occurrences, and the two routes by which a value becomes an
entity.

**Field routing** — a value is extracted because of the field it sat in. Each
extractor owns a small table of literal field names. The table is a routing
hint, not a schema: nothing is canonicalised, no definition is looked up, and
the field name is recorded on the entity exactly as the rule wrote it. Lookup
is case-insensitive because formats disagree on casing; the stored value and
field are untouched.

**Shape scanning** — a value is extracted because of its literal form. An IPv4
address or a 64-character hex string is recognisable without reading any
surrounding syntax. Scanning never interprets operators, grouping or negation,
so it says nothing about what the rule does with the value.

Both routes read :class:`~src.entities.models.ExtractionContext`, and the
occurrences it carries come from wherever the rule states its detection. A
format holding named blocks is walked; a format holding a single query
expression is read clause by clause by :func:`query_occurrences`. Neither
traversal knows which format it is serving, which is why one set of extractors
covers both.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Final, Protocol, runtime_checkable

from src.parser.models import ParsedRule
from src.parser.types import RuleValue

from .models import Entity, ExtractionContext, FieldOccurrence, TextScope
from .types import EntityType, RuleSection

MODIFIER_SEPARATOR: Final[str] = "|"

SUBFIELD_SEPARATOR: Final[str] = "."

NORMALISED_SUBFIELDS: Final[frozenset[str]] = frozenset({"caseless"})
"""The multi-field suffixes read as a modifier rather than as part of the name.

Closed, and closed on evidence: ``.caseless`` occurs 169 times across the kuery
corpus and ``.keyword`` and ``.text`` occur not at all, while one real ECS field
ends in one of those two. Widening this set would rename fields the corpus
actually defines.
"""

FieldTable = Mapping[str, EntityType]
PatternTable = Mapping[EntityType, re.Pattern[str]]

_SEPARATORS: Final[str] = r"(?::|==|!=)"
"""The separators the corpus writes between a field and its value.

``:`` in Kuery and Lucene, ``==`` and ``!=`` in EQL. Written once and used by
both the clause reader and :func:`introduces_a_value`, so the two cannot come to
disagree about what marks a field.
"""

_CLAUSE_HEAD: Final[re.Pattern[str]] = re.compile(
    rf"(?P<field>[A-Za-z_@][A-Za-z0-9_.@\-]*)\s*{_SEPARATORS}\s*"
)
"""A field name followed by the separator that introduces its value.

Which separator was used is deliberately not captured — see
:func:`query_occurrences`.
"""

_SEPARATOR: Final[re.Pattern[str]] = re.compile(rf"\s*{_SEPARATORS}")

_GROUP_MEMBER: Final[re.Pattern[str]] = re.compile(r"\"[^\"]*\"|[^\s()]+")
"""One member of a parenthesised value list, quoted or bare."""

_NEGATION: Final[re.Pattern[str]] = re.compile(r"not\b\s*", re.IGNORECASE)
"""A negation standing where a value would.

Anchored by :meth:`re.Pattern.match`'s own offset rather than by ``\\A``, which
would tie the match to the start of the whole query instead of the position
being read.
"""

_QUERY_KEYWORDS: Final[frozenset[str]] = frozenset({"and", "or", "not"})
"""Words that join clauses rather than naming a field or standing as a value."""

_OPENERS: Final[str] = "("
_CLOSERS: Final[str] = ")"
_QUOTE: Final[str] = '"'
_ESCAPE: Final[str] = "\\"


@runtime_checkable
class Extractor(Protocol):
    """Extracts one family of entities from a rule."""

    @property
    def name(self) -> str:
        """Return this extractor's identifier, recorded on every entity it makes."""
        ...

    @property
    def entity_types(self) -> tuple[EntityType, ...]:
        """Return the entity types this extractor can produce."""
        ...

    def extract(self, context: ExtractionContext) -> tuple[Entity, ...]:
        """Return the entities found in the rule, in the order they were found."""
        ...


def split_field(key: str) -> tuple[str, tuple[str, ...]]:
    """Split a field key into the name to look up and the modifiers applied to it.

    Two formats write a modifier onto a field name, and neither of them changes
    the name. Sigma appends its matching semantics after a pipe —
    ``Image|endswith`` — and Elasticsearch addresses a multi-field through a
    dotted subfield — ``process.name.caseless``. Both of those name ``Image`` and
    ``process.name``; the tail says how a value is compared, not what is being
    compared. Returning both as modifiers lets one caller read one shape.

    The key itself is never rewritten. An entity keeps ``source_field`` exactly
    as the rule wrote it, and only the name used to consult a table is the base,
    which is the arrangement Sigma modifiers have always had.

    ``caseless`` is the only subfield recognised, because it is the only one the
    corpus writes. ``.keyword`` and ``.text`` are deliberately left alone: no
    rule states them, and an ECS field of its own does end in one of them, so
    stripping that tail would rename a real field rather than reveal it.
    """
    head, modifiers = _split_modifiers(key)
    base, subfield = _split_subfield(head)
    return base, (*modifiers, *subfield)


def _split_modifiers(key: str) -> tuple[str, tuple[str, ...]]:
    """Return a key without its pipe-separated modifiers, and those modifiers."""
    if MODIFIER_SEPARATOR not in key:
        return key, ()
    head, _, tail = key.partition(MODIFIER_SEPARATOR)
    return head, tuple(part for part in tail.split(MODIFIER_SEPARATOR) if part)


def _split_subfield(name: str) -> tuple[str, tuple[str, ...]]:
    """Return a field name without a recognised multi-field suffix.

    The base must be non-empty, so a name that is nothing but the suffix is left
    as it stands rather than reduced to nothing.
    """
    base, separator, tail = name.rpartition(SUBFIELD_SEPARATOR)
    if separator and base and tail.lower() in NORMALISED_SUBFIELDS:
        return base, (tail,)
    return name, ()


def introduces_a_value(text: str, position: int) -> bool:
    """Return whether a separator stands at this offset, naming what precedes it.

    The one structural fact a query states about a bare token: a field is
    followed by a separator and a value is not. ``process.name`` in
    ``process.name:iodine`` is a field; ``lsass.exe`` in ``... and lsass.exe`` is
    a value that happens to share a field name's shape.

    Whitespace may stand between the two, because a query may be written
    ``process.name : iodine``.
    """
    return _SEPARATOR.match(text, position) is not None


def query_occurrences(
    query: str,
    *,
    section: RuleSection = RuleSection.DETECTION,
) -> tuple[FieldOccurrence, ...]:
    """Return the field-and-value pairs a single query expression states.

    A clause is a field, a separator and a value; a parenthesised value states
    several, and each one is its own occurrence carrying the same field. That is
    the whole of what is read. The pair is the only thing a later stage needs
    from a query, and it is the only thing recoverable without a grammar.

    **Nothing is interpreted.** Which separator joined the pair is not recorded,
    a negated clause states the same pair as an affirmative one, and how clauses
    combine is not read at all. Stage-09 reports what a rule references, not what
    it does with it, and a query says ``process.name`` refers to ``iodine``
    whether it is matching or excluding it. Recording the operator would be the
    first half of evaluating the rule, and this layer does not evaluate.

    **A clause that cannot be read yields nothing.** An unterminated group or
    literal returns no occurrence rather than a pair assembled from a guess,
    because a wrong pair is worse than a missing one: it would send a value to
    the wrong field and a later stage would treat it as the rule's own.

    Ordering follows the query, and every occurrence is addressed by the offset
    the clause begins at, so two runs over one query produce identical results.
    """
    found: list[FieldOccurrence] = []
    index = 0
    while index < len(query):
        head = _CLAUSE_HEAD.search(query, index)
        if head is None:
            break
        index = head.end()
        if head.group("field").lower() in _QUERY_KEYWORDS:
            continue
        read = _read_value(query, _skip_negation(query, index))
        if read is None:
            continue
        values, index = read
        found.extend(
            _query_occurrence(head.group("field"), value, head.start(), position, section)
            for position, value in enumerate(values)
        )
    return tuple(found)


def build_context(rule: ParsedRule) -> ExtractionContext:
    """Walk a parsed rule once and return the context extractors share.

    Both detection shapes reach the same list. Named blocks are walked and a
    query is read, so an extractor sees occurrences without learning which
    format produced them.

    Only the walked occurrences become text scopes. A query already contributes
    one scope of its own — the whole expression — and scanning each of its
    values a second time would report the same address twice from a single
    reading of a single string.
    """
    stated = tuple(_walk_detection(rule))
    scopes = tuple(_text_scopes(rule, stated))
    return ExtractionContext(
        rule=rule,
        occurrences=(*stated, *query_occurrences(rule.detection.query or "")),
        scopes=scopes,
    )


def route_fields(
    context: ExtractionContext,
    table: FieldTable,
    *,
    extractor: str,
) -> list[Entity]:
    """Emit an entity for each occurrence whose base field is in the table."""
    found: list[Entity] = []
    for occurrence in context.occurrences:
        base, _ = split_field(occurrence.field)
        entity_type = table.get(base.strip().lower())
        if entity_type is None:
            continue
        found.append(
            Entity(
                entity_type=entity_type,
                value=occurrence.value,
                source_field=occurrence.field,
                location=occurrence.location,
                section=occurrence.section,
                extractor=extractor,
            )
        )
    return found


def scan_shapes(
    context: ExtractionContext,
    patterns: PatternTable,
    *,
    extractor: str,
    skip_fields: FieldTable | None = None,
) -> list[Entity]:
    """Emit an entity for each literal shape found in the rule's text.

    ``skip_fields`` suppresses scanning of values this extractor already routed
    by field name, so one extractor does not report the same value twice.
    Suppression is local: a value found by a *different* extractor is still
    reported, because deduplication across extractors is forbidden.
    """
    found: list[Entity] = []
    for scope in context.scopes:
        if skip_fields is not None:
            base, _ = split_field(scope.source_field)
            if base.strip().lower() in skip_fields:
                continue
        for entity_type, pattern in patterns.items():
            for match in pattern.finditer(scope.text):
                found.append(
                    Entity(
                        entity_type=entity_type,
                        value=match.group(0),
                        source_field=scope.source_field,
                        location=scope.location,
                        section=scope.section,
                        extractor=extractor,
                    )
                )
    return found


def values_to_entities(
    values: Iterable[str],
    *,
    entity_type: EntityType,
    source_field: str,
    location: str,
    section: RuleSection,
    extractor: str,
) -> list[Entity]:
    """Emit one entity per value in a plain sequence, preserving order."""
    return [
        Entity(
            entity_type=entity_type,
            value=value,
            source_field=source_field,
            location=f"{location}[{index}]",
            section=section,
            extractor=extractor,
        )
        for index, value in enumerate(values)
    ]


def _query_occurrence(
    field: str,
    value: str,
    start: int,
    position: int,
    section: RuleSection,
) -> FieldOccurrence:
    """Build one occurrence read out of a query, addressed by where it sits.

    The address is the offset the clause begins at, with the member's position
    appended when the clause stated several values. Two clauses cannot begin at
    one offset, so no two occurrences of a query share an address.
    """
    location = f"detection.query[{start}]"
    return FieldOccurrence(
        field=field,
        value=value,
        location=f"{location}[{position}]" if position else location,
        section=section,
    )


def _skip_negation(text: str, start: int) -> int:
    """Return the offset past a leading ``not``, which negates rather than values."""
    negation = _NEGATION.match(text, start)
    return negation.end() if negation is not None else start


def _read_value(text: str, start: int) -> tuple[tuple[str, ...], int] | None:
    """Return the values one clause states and where the clause ends.

    ``None`` when the clause cannot be read, which is the answer whenever a
    guess would be needed: a group or a literal that never closes, or a
    separator with nothing after it.
    """
    if start >= len(text):
        return None
    if text[start] in _OPENERS:
        return _read_group(text, start)
    if text[start] == _QUOTE:
        return _read_literal(text, start)
    return _read_token(text, start)


def _read_group(text: str, start: int) -> tuple[tuple[str, ...], int] | None:
    """Return the members of a parenthesised value list, or ``None`` if unclosed.

    Depth is tracked so a nested group closes the outer one only when its own
    parenthesis has been matched, and a parenthesis inside a literal is a
    character rather than a delimiter.
    """
    depth = 0
    index = start
    quote = False
    while index < len(text):
        char = text[index]
        if quote:
            if char == _ESCAPE:
                index += 2
                continue
            if char == _QUOTE:
                quote = False
        elif char == _QUOTE:
            quote = True
        elif char in _OPENERS:
            depth += 1
        elif char in _CLOSERS:
            depth -= 1
            if depth == 0:
                body = text[start + 1 : index]
                members = tuple(
                    _unquote(match.group(0))
                    for match in _GROUP_MEMBER.finditer(body)
                    if match.group(0).lower() not in _QUERY_KEYWORDS
                )
                return (members, index + 1) if members else None
        index += 1
    return None


def _read_literal(text: str, start: int) -> tuple[tuple[str, ...], int] | None:
    """Return a quoted value, or ``None`` when the literal never closes."""
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == _ESCAPE:
            index += 2
            continue
        if char == _QUOTE:
            return ((text[start + 1 : index],), index + 1)
        index += 1
    return None


def _read_token(text: str, start: int) -> tuple[tuple[str, ...], int] | None:
    """Return a bare value, which ends at whitespace or a parenthesis."""
    index = start
    while index < len(text) and not text[index].isspace() and text[index] not in "()":
        index += 1
    value = text[start:index]
    return ((value, ), index) if value else None


def _unquote(value: str) -> str:
    """Return a group member without the quotes that delimited it."""
    if len(value) >= 2 and value.startswith(_QUOTE) and value.endswith(_QUOTE):
        return value[1:-1]
    return value


def _walk_detection(rule: ParsedRule) -> list[FieldOccurrence]:
    """Flatten the detection body into field-and-value pairs."""
    found: list[FieldOccurrence] = []
    for name, block in rule.detection.definitions.items():
        _walk(block, field="", path=f"detection.{name}", found=found)
    return found


def _walk(value: RuleValue, *, field: str, path: str, found: list[FieldOccurrence]) -> None:
    """Recurse through a detection block, collecting scalar leaves."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = str(key)
            _walk(item, field=child, path=f"{path}.{child}", found=found)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _walk(item, field=field, path=f"{path}[{index}]", found=found)
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (str, int, float)):
        found.append(FieldOccurrence(field=field, value=str(value), location=path))


def _text_scopes(rule: ParsedRule, occurrences: Sequence[FieldOccurrence]) -> list[TextScope]:
    """Return the text blocks literal patterns may be scanned over.

    Detection values and the query only. Titles, descriptions and references are
    prose or already extracted elsewhere, and scanning them would manufacture
    entities the detection never referenced.
    """
    scopes = [
        TextScope(
            text=occurrence.value,
            source_field=occurrence.field,
            location=occurrence.location,
        )
        for occurrence in occurrences
    ]
    if rule.detection.query:
        scopes.append(
            TextScope(
                text=rule.detection.query,
                source_field="query",
                location="detection.query",
            )
        )
    return scopes
