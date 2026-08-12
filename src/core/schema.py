"""Response schema.

A small, closed description language for the JSON a reasoning operation must
return, plus the strict checker that holds a response to it and the renderer
that states it to the model.

One declaration, two consumers. The text the model is shown and the rules the
response is judged by come from the same :class:`ObjectSpec`, so the contract
cannot drift between the prompt and the validator.

The checker is strict in the same sense Stage-07's JSON parser is strict. It
does not coerce ``"3"`` to ``3``, does not accept ``null`` for an absent value,
does not ignore a field the schema never declared, and does not stop at the
first fault. It reports what is wrong and leaves the response untouched.

Two rules are worth stating explicitly because they are easy to get wrong:

* A JSON boolean is not an integer. Python says otherwise, so every numeric
  check excludes ``bool`` before looking at the value.
* Every string is a single line, as ``prompts/shared/output.md`` requires.
  Structure is expressed with objects and arrays, never with newlines inside a
  string.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from src.llm.types import JSONValue

_INDENT: Final[str] = "  "
_ENUM_JOIN: Final[str] = " | "


class FieldKind(StrEnum):
    """The shape a schema field takes."""

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    OBJECT = "object"
    OBJECT_ARRAY = "object_array"
    STRING_ARRAY = "string_array"
    STRING_MAP = "string_map"


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One field of a response object.

    Every declared field is required. ``prompts/shared/output.md`` tells the
    model to return an empty array or an empty object where it has no value, and
    never ``null``, so optionality is expressed by ``allow_empty`` rather than by
    letting a field disappear.
    """

    name: str
    kind: FieldKind
    description: str
    enum: tuple[str, ...] = ()
    const: str = ""
    minimum: float | None = None
    maximum: float | None = None
    allow_empty: bool = False
    min_items: int = 0
    spec: ObjectSpec | None = None

    def __post_init__(self) -> None:
        """Reject a field declaration that cannot describe a value."""
        if self.kind in _NESTED_KINDS and self.spec is None:
            raise ValueError(f"field {self.name!r} of kind {self.kind.value} needs a spec")
        if self.kind not in _NESTED_KINDS and self.spec is not None:
            raise ValueError(f"field {self.name!r} of kind {self.kind.value} takes no spec")
        if self.enum and self.kind is not FieldKind.STRING:
            raise ValueError(f"field {self.name!r} may only enumerate string values")
        if self.const and self.kind is not FieldKind.STRING:
            raise ValueError(f"field {self.name!r} may only fix a string value")

    @property
    def constraint_text(self) -> str:
        """Return the field's constraints as one line, for the prompt."""
        parts: list[str] = [self.kind.value]
        if self.const:
            parts.append(f"exactly {self.const!r}")
        if self.enum:
            parts.append("one of: " + ", ".join(self.enum))
        if self.minimum is not None or self.maximum is not None:
            low = "" if self.minimum is None else f"{_number(self.minimum)}"
            high = "" if self.maximum is None else f"{_number(self.maximum)}"
            parts.append(f"range {low}..{high}")
        if self.min_items:
            parts.append(f"at least {self.min_items} item(s)")
        if self.kind is FieldKind.STRING and not self.allow_empty and not self.const:
            parts.append("non-empty")
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class ObjectSpec:
    """A JSON object described field by field."""

    name: str
    description: str
    fields: tuple[FieldSpec, ...] = field(default_factory=tuple)

    def field_names(self) -> tuple[str, ...]:
        """Return the declared field names, in declaration order."""
        return tuple(item.name for item in self.fields)


_NESTED_KINDS: Final[frozenset[FieldKind]] = frozenset(
    {FieldKind.OBJECT, FieldKind.OBJECT_ARRAY}
)


@dataclass(frozen=True, slots=True)
class SchemaIssue:
    """One structural fault, addressed by its path in the document."""

    path: str
    detail: str

    def __str__(self) -> str:
        """Return the issue rendered as ``path: detail``."""
        return f"{self.path}: {self.detail}"


@dataclass(frozen=True, slots=True)
class SchemaValidator:
    """Checks a parsed JSON document against an object specification."""

    spec: ObjectSpec

    def validate(self, document: JSONValue) -> tuple[SchemaIssue, ...]:
        """Return every structural fault, in document order."""
        return tuple(self._object(document, self.spec, "$"))

    def _object(self, value: JSONValue, spec: ObjectSpec, path: str) -> Iterator[SchemaIssue]:
        """Yield the faults of one object."""
        if not isinstance(value, Mapping):
            yield SchemaIssue(path, f"expected an object, got {_type_name(value)}")
            return
        for declared in spec.fields:
            child = f"{path}.{declared.name}"
            if declared.name not in value:
                yield SchemaIssue(child, f"required field is missing ({declared.kind.value})")
                continue
            yield from self._field(value[declared.name], declared, child)
        for extra in sorted(name for name in value if name not in spec.field_names()):
            yield SchemaIssue(
                f"{path}.{extra}",
                "field is not defined by the schema and must not be returned",
            )

    def _field(self, value: JSONValue, declared: FieldSpec, path: str) -> Iterator[SchemaIssue]:
        """Yield the faults of one field's value."""
        match declared.kind:
            case FieldKind.STRING:
                yield from self._string(value, declared, path)
            case FieldKind.INTEGER:
                yield from self._integer(value, declared, path)
            case FieldKind.NUMBER:
                yield from self._number(value, declared, path)
            case FieldKind.OBJECT:
                assert declared.spec is not None  # noqa: S101 - guarded by FieldSpec
                yield from self._object(value, declared.spec, path)
            case FieldKind.OBJECT_ARRAY:
                yield from self._object_array(value, declared, path)
            case FieldKind.STRING_ARRAY:
                yield from self._string_array(value, declared, path)
            case FieldKind.STRING_MAP:
                yield from self._string_map(value, path)

    def _string(self, value: JSONValue, declared: FieldSpec, path: str) -> Iterator[SchemaIssue]:
        """Yield the faults of a string value."""
        if not isinstance(value, str):
            yield SchemaIssue(path, f"expected a string, got {_type_name(value)}")
            return
        if "\n" in value or "\r" in value:
            yield SchemaIssue(path, "string must be a single line")
        if declared.const and value != declared.const:
            yield SchemaIssue(path, f"expected {declared.const!r}, got {value!r}")
            return
        if not value.strip() and not declared.allow_empty:
            yield SchemaIssue(path, "string must not be empty")
            return
        if declared.enum and value not in declared.enum:
            if declared.allow_empty and not value:
                return
            yield SchemaIssue(
                path,
                f"{value!r} is not one of: " + ", ".join(declared.enum),
            )

    def _integer(self, value: JSONValue, declared: FieldSpec, path: str) -> Iterator[SchemaIssue]:
        """Yield the faults of an integer value."""
        if isinstance(value, bool) or not isinstance(value, int):
            yield SchemaIssue(path, f"expected an integer, got {_type_name(value)}")
            return
        yield from self._range(float(value), declared, path)

    def _number(self, value: JSONValue, declared: FieldSpec, path: str) -> Iterator[SchemaIssue]:
        """Yield the faults of a numeric value."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            yield SchemaIssue(path, f"expected a number, got {_type_name(value)}")
            return
        yield from self._range(float(value), declared, path)

    def _range(self, value: float, declared: FieldSpec, path: str) -> Iterator[SchemaIssue]:
        """Yield a fault when a number falls outside its declared range."""
        if declared.minimum is not None and value < declared.minimum:
            yield SchemaIssue(
                path, f"{_number(value)} is below the minimum {_number(declared.minimum)}"
            )
        if declared.maximum is not None and value > declared.maximum:
            yield SchemaIssue(
                path, f"{_number(value)} is above the maximum {_number(declared.maximum)}"
            )

    def _object_array(
        self,
        value: JSONValue,
        declared: FieldSpec,
        path: str,
    ) -> Iterator[SchemaIssue]:
        """Yield the faults of an array of objects."""
        assert declared.spec is not None  # noqa: S101 - guarded by FieldSpec
        if not _is_array(value):
            yield SchemaIssue(path, f"expected an array, got {_type_name(value)}")
            return
        items = list(value)  # type: ignore[arg-type]
        if len(items) < declared.min_items:
            yield SchemaIssue(
                path, f"expected at least {declared.min_items} item(s), got {len(items)}"
            )
        for index, item in enumerate(items):
            yield from self._object(item, declared.spec, f"{path}[{index}]")

    def _string_array(
        self,
        value: JSONValue,
        declared: FieldSpec,
        path: str,
    ) -> Iterator[SchemaIssue]:
        """Yield the faults of an array of strings."""
        if not _is_array(value):
            yield SchemaIssue(path, f"expected an array, got {_type_name(value)}")
            return
        items = list(value)  # type: ignore[arg-type]
        if len(items) < declared.min_items:
            yield SchemaIssue(
                path, f"expected at least {declared.min_items} item(s), got {len(items)}"
            )
        for index, item in enumerate(items):
            child = f"{path}[{index}]"
            if not isinstance(item, str):
                yield SchemaIssue(child, f"expected a string, got {_type_name(item)}")
                continue
            if "\n" in item or "\r" in item:
                yield SchemaIssue(child, "string must be a single line")
            if not item.strip():
                yield SchemaIssue(child, "string must not be empty")
            elif declared.enum and item not in declared.enum:
                yield SchemaIssue(child, f"{item!r} is not one of: " + ", ".join(declared.enum))

    def _string_map(self, value: JSONValue, path: str) -> Iterator[SchemaIssue]:
        """Yield the faults of a string-to-string mapping."""
        if not isinstance(value, Mapping):
            yield SchemaIssue(path, f"expected an object, got {_type_name(value)}")
            return
        for key in sorted(value):
            entry = value[key]
            if not isinstance(entry, str):
                yield SchemaIssue(f"{path}.{key}", f"expected a string, got {_type_name(entry)}")
            elif "\n" in entry or "\r" in entry:
                yield SchemaIssue(f"{path}.{key}", "string must be a single line")


def render_object_spec(spec: ObjectSpec) -> str:
    """Return the specification as prompt text.

    Two parts: the exact object skeleton, and one rule line per field addressed
    by its path. Generated from the specification, so the model is shown the
    same contract the validator applies.
    """
    skeleton = json.dumps(_skeleton(spec), indent=2, ensure_ascii=False)
    lines = [
        f"The complete response object for this operation is `{spec.name}`.",
        spec.description,
        "",
        "```json",
        skeleton,
        "```",
        "",
        "Field rules:",
        "",
    ]
    lines.extend(f"- `{path}` — {text}" for path, text in _rule_lines(spec, ""))
    lines.extend(
        (
            "",
            "Every field above is required. Return an empty array or an empty object where "
            "you have no value, never `null` and never a placeholder. Return no field that "
            "is not listed above.",
        )
    )
    return "\n".join(lines)


def json_schema(spec: ObjectSpec) -> dict[str, JSONValue]:
    """Return the specification as a JSON Schema document.

    A third consumer of the same declaration, alongside the prompt text and the
    validator: a provider that can constrain its own decoding is handed the
    shape directly, rather than being asked in prose and checked afterwards.

    Deliberately conservative. Only the keywords every JSON Schema consumer
    understands are emitted — ``type``, ``properties``, ``required``, ``enum``,
    ``items``, ``description`` and numeric bounds. Constraints a provider might
    not implement, such as ``additionalProperties`` and ``minItems``, are left
    out here and enforced by :class:`SchemaValidator` after the fact, so a
    provider that ignores them cannot make a malformed response look accepted.
    """
    return {
        "type": "object",
        "description": spec.description,
        "properties": {item.name: _json_field(item) for item in spec.fields},
        "required": [item.name for item in spec.fields],
    }


def _json_field(declared: FieldSpec) -> dict[str, JSONValue]:
    """Return the JSON Schema fragment describing one field."""
    node: dict[str, JSONValue] = {"description": declared.description}
    match declared.kind:
        case FieldKind.STRING:
            node["type"] = "string"
            if declared.const:
                node["enum"] = [declared.const]
            elif declared.enum:
                node["enum"] = list(declared.enum)
        case FieldKind.INTEGER | FieldKind.NUMBER:
            node["type"] = "integer" if declared.kind is FieldKind.INTEGER else "number"
            if declared.minimum is not None:
                node["minimum"] = declared.minimum
            if declared.maximum is not None:
                node["maximum"] = declared.maximum
        case FieldKind.OBJECT:
            assert declared.spec is not None
            node = {**json_schema(declared.spec), "description": declared.description}
        case FieldKind.OBJECT_ARRAY:
            assert declared.spec is not None
            node["type"] = "array"
            node["items"] = json_schema(declared.spec)
        case FieldKind.STRING_ARRAY:
            node["type"] = "array"
            item: dict[str, JSONValue] = {"type": "string"}
            if declared.enum:
                item["enum"] = list(declared.enum)
            node["items"] = item
        case FieldKind.STRING_MAP:
            node["type"] = "object"
    return node


def _skeleton(spec: ObjectSpec) -> dict[str, object]:
    """Return the example object a specification describes."""
    return {item.name: _example(item) for item in spec.fields}


def _example(declared: FieldSpec) -> object:
    """Return the example value of one field."""
    match declared.kind:
        case FieldKind.STRING:
            if declared.const:
                return declared.const
            if declared.enum:
                return _ENUM_JOIN.join(declared.enum)
            return "string"
        case FieldKind.INTEGER:
            return 0
        case FieldKind.NUMBER:
            return 0.0
        case FieldKind.OBJECT:
            assert declared.spec is not None  # noqa: S101 - guarded by FieldSpec
            return _skeleton(declared.spec)
        case FieldKind.OBJECT_ARRAY:
            assert declared.spec is not None  # noqa: S101 - guarded by FieldSpec
            return [_skeleton(declared.spec)]
        case FieldKind.STRING_ARRAY:
            return [_ENUM_JOIN.join(declared.enum)] if declared.enum else ["string"]
        case FieldKind.STRING_MAP:
            return {"key": "value"}


def _rule_lines(spec: ObjectSpec, prefix: str) -> Iterator[tuple[str, str]]:
    """Yield one ``(path, rule)`` pair per field, depth first in declaration order."""
    for declared in spec.fields:
        path = f"{prefix}{declared.name}"
        yield path, f"{declared.constraint_text}. {declared.description}"
        if declared.spec is None:
            continue
        child = f"{path}[]." if declared.kind is FieldKind.OBJECT_ARRAY else f"{path}."
        yield from _rule_lines(declared.spec, child)


def _is_array(value: JSONValue) -> bool:
    """Return whether a JSON value is an array rather than a string or mapping."""
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _type_name(value: JSONValue) -> str:
    """Return the JSON type name of a value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, Mapping):
        return "object"
    if _is_array(value):
        return "array"
    return type(value).__name__


def _number(value: float) -> str:
    """Return a number rendered without a trailing ``.0`` where it is whole."""
    return str(int(value)) if float(value).is_integer() else str(value)
