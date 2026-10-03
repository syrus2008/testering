"""Canonical JSON (ACET-FMT-003, ACC-067).

Specification of the canonical form used for fingerprints and signatures:

1. UTF-8 encoding, no BOM, non-ASCII characters emitted as-is (not escaped).
2. Object keys sorted by Unicode code point; keys MUST be strings.
3. No insignificant whitespace (separators ``,`` and ``:``).
4. Allowed scalar types: ``str``, ``int``, ``bool``, ``None``. Floats are
   rejected: fingerprinted objects must not depend on float formatting.
5. Strings are NFC-normalized before encoding so that visually identical
   Unicode inputs produce identical bytes (FI-015 / ACC-064).
6. Tuples are encoded as arrays. Any other type is rejected.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any


class CanonicalJsonError(TypeError):
    pass


def _normalize(value: Any, path: str = "$", floats: bool = False) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not floats:
            raise CanonicalJsonError(f"float not allowed in canonical JSON at {path}")
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalJsonError(f"non-finite float at {path}")
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalJsonError(f"non-string key {k!r} at {path}")
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise CanonicalJsonError(f"duplicate key after NFC normalization at {path}: {nk!r}")
            out[nk] = _normalize(v, f"{path}.{nk}", floats)
        return out
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [_normalize(v, f"{path}[{i}]", floats) for i, v in enumerate(value)]
    raise CanonicalJsonError(f"unsupported type {type(value).__name__} at {path}")


def canonical_json(value: Any) -> bytes:
    """Serialize ``value`` to canonical JSON bytes."""
    return json.dumps(
        _normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    """SHA-256 (lowercase hex) of the canonical JSON encoding of ``value``."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def stable_json(value: Any) -> bytes:
    """Canonical form that also allows finite floats (shortest round-trip repr).

    Used for persisted payloads and derived outputs, which must be byte-stable
    across runs (determinism classes D0/D1) but may carry measurements. Never
    used for identities/fingerprints, which use :func:`canonical_json`.
    """
    return json.dumps(
        _normalize(value, "$", True), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def stable_hash(value: Any) -> str:
    """SHA-256 of :func:`stable_json` — for comparing measured outputs (D1 determinism), not identities."""
    return hashlib.sha256(stable_json(value)).hexdigest()
