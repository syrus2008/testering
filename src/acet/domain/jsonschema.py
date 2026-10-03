"""Minimal JSON Schema (2020-12 subset) validator for ACET's own contracts.

Supports: type, const, enum, required, properties, additionalProperties (bool or
schema), items, minItems, maxItems, uniqueItems, minLength, maxLength, pattern,
minimum, maximum, $ref to "#/$defs/...". Unknown keywords are ignored except that
``format`` is documentation only. This is intentionally small: contracts are
ours, and a missing keyword would be caught by ``test_schema_keywords_supported``.
"""

from __future__ import annotations

import json
import re
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

SUPPORTED = frozenset(
    {
        "$schema",
        "$id",
        "$defs",
        "$ref",
        "title",
        "description",
        "type",
        "const",
        "enum",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "format",
        "default",
        "examples",
    }
)

_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "boolean": (bool,),
    "null": (type(None),),
    "integer": (int,),
    "number": (int, float),
}


class SchemaValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors[:5]))
        self.errors = errors


def _is_type(value: Any, t: str) -> bool:
    if t in ("integer", "number") and isinstance(value, bool):
        return False
    if t == "integer" and isinstance(value, float):
        return value.is_integer()
    return isinstance(value, _TYPES[t])


def _validate(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str, errors: list[str]) -> None:
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            errors.append(f"{path}: unsupported $ref {ref}")
            return
        _validate(value, root["$defs"][ref.split("/")[-1]], root, path, errors)
        return
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, t) for t in types):
            errors.append(f"{path}: expected {types}, got {type(value).__name__}")
            return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match pattern")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems")
        if schema.get("uniqueItems"):
            seen = [json.dumps(v, sort_keys=True) for v in value]
            if len(seen) != len(set(seen)):
                errors.append(f"{path}: items not unique")
        if isinstance(schema.get("items"), dict):
            for i, v in enumerate(value):
                _validate(v, schema["items"], root, f"{path}[{i}]", errors)
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}: missing required {req!r}")
        props = schema.get("properties", {})
        addl = schema.get("additionalProperties", True)
        for k, v in value.items():
            if k in props:
                _validate(v, props[k], root, f"{path}.{k}", errors)
            elif addl is False:
                errors.append(f"{path}: unexpected property {k!r}")
            elif isinstance(addl, dict):
                _validate(v, addl, root, f"{path}.{k}", errors)


def validate(value: Any, schema: dict[str, Any]) -> None:
    errors: list[str] = []
    _validate(value, schema, schema, "$", errors)
    if errors:
        raise SchemaValidationError(errors)


def schema_dir() -> Path:
    """Location of the bundled JSON schemas (``acet/schemas/v1``)."""
    return Path(str(resources.files("acet"))) / "schemas" / "v1"


@cache
def load_schema(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((schema_dir() / f"{name}.schema.json").read_text(encoding="utf-8"))
    return data


def validate_named(value: Any, name: str) -> None:
    validate(value, load_schema(name))
