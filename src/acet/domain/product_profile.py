"""Product Profile v2 (spec §82). Declarative only (ACET-PROF-001, ACC-097).

The Core contains no product-specific branch (ACET-PROD-003): anything specific
to a tracked product lives in a validated, data-only profile like this one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from acet.domain.enums import ComponentPresence, ComponentRole
from acet.domain.error_codes import AcetError

SCHEMA_VERSION = 2

_LIST_KEYS = (
    "expected_roles",
    "optional_roles",
    "filename_hints",
    "signature_hints",
    "version_extractors",
    "channel_hints",
    "completeness_rules",
)
_ALLOWED_KEYS = frozenset({"schema_version", "product_name", "notes", *_LIST_KEYS})
_MAX_STR = 1024
_MAX_ITEMS = 256


def _check_plain(value: Any, path: str, depth: int = 0) -> None:
    """Only JSON-like plain data, bounded. No code objects, no callables."""
    if depth > 4:
        raise AcetError("ACET-PROF-001", f"nesting too deep at {path}")
    if value is None or isinstance(value, bool | int):
        return
    if isinstance(value, str):
        if len(value) > _MAX_STR:
            raise AcetError("ACET-PROF-001", f"string too long at {path}")
        return
    if isinstance(value, list):
        if len(value) > _MAX_ITEMS:
            raise AcetError("ACET-PROF-001", f"too many items at {path}")
        for i, v in enumerate(value):
            _check_plain(v, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise AcetError("ACET-PROF-001", f"non-string key at {path}")
            _check_plain(v, f"{path}.{k}", depth + 1)
        return
    raise AcetError("ACET-PROF-001", f"unsupported value type {type(value).__name__} at {path}")


@dataclass(frozen=True)
class ProductProfile:
    product_name: str
    expected_roles: tuple[ComponentRole, ...] = ()
    optional_roles: tuple[ComponentRole, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    @classmethod
    def empty(cls, product_name: str) -> ProductProfile:
        return cls.parse({"schema_version": SCHEMA_VERSION, "product_name": product_name})

    @classmethod
    def parse(cls, data: Any) -> ProductProfile:
        if not isinstance(data, dict):
            raise AcetError("ACET-PROF-001", "profile must be a JSON object")
        unknown = set(data) - _ALLOWED_KEYS
        if unknown:
            # INV-016: unknown schema is refused, never partially guessed.
            raise AcetError("ACET-PROF-001", f"unknown keys: {sorted(unknown)}")
        if data.get("schema_version") != SCHEMA_VERSION:
            raise AcetError("ACET-PROF-001", f"schema_version must be {SCHEMA_VERSION}")
        name = data.get("product_name")
        if not isinstance(name, str) or not name.strip():
            raise AcetError("ACET-PROF-001", "product_name is required")
        for key in _LIST_KEYS:
            if key in data and not isinstance(data[key], list):
                raise AcetError("ACET-PROF-001", f"{key} must be a list")
        _check_plain(data, "$")

        def roles(key: str) -> tuple[ComponentRole, ...]:
            try:
                return tuple(ComponentRole(r) for r in data.get(key, []))
            except ValueError as exc:
                raise AcetError("ACET-PROF-001", f"{key}: {exc}") from None

        return cls(
            product_name=name,
            expected_roles=roles("expected_roles"),
            optional_roles=roles("optional_roles"),
            raw=dict(data),
        )

    def completeness(self, present_roles: set[ComponentRole]) -> dict[ComponentRole, ComponentPresence]:
        """ACC-047: an expected role not observed is UNKNOWN, never ABSENT."""
        return {
            role: ComponentPresence.PRESENT if role in present_roles else ComponentPresence.UNKNOWN
            for role in self.expected_roles
        }
