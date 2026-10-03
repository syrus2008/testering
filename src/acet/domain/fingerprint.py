"""Build fingerprint (spec §12).

build_fingerprint = SHA256(canonical_json(sorted([{role, artifact_sha256, purpose, ordinal}])))

Version labels, dates, local paths and file names never participate.

``ordinal`` disambiguates *identical* (role, artifact, purpose) triples only —
e.g. the same file shipped twice in the same role. It is assigned after
sorting, therefore any permutation of the input yields the same fingerprint
(PROP-002 / ACC-113).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from acet.domain.canonical import canonical_hash, canonical_json
from acet.domain.enums import ComponentRole
from acet.domain.ids import require_sha256

DEFAULT_PURPOSE = "primary"


@dataclass(frozen=True, order=True)
class ComponentEntry:
    role: ComponentRole
    artifact_sha256: str
    purpose: str = DEFAULT_PURPOSE

    def __post_init__(self) -> None:
        require_sha256(self.artifact_sha256)
        if not self.purpose:
            raise ValueError("purpose must be non-empty")


@dataclass(frozen=True)
class OrdinalEntry:
    role: ComponentRole
    artifact_sha256: str
    purpose: str
    ordinal: int

    def as_json(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "artifact_sha256": self.artifact_sha256,
            "purpose": self.purpose,
            "ordinal": self.ordinal,
        }


def assign_ordinals(entries: Iterable[ComponentEntry]) -> list[OrdinalEntry]:
    """Deterministically sort entries and number duplicates 0..n-1."""
    seen: Counter[tuple[str, str, str]] = Counter()
    out: list[OrdinalEntry] = []
    for e in sorted(entries, key=lambda x: (x.role.value, x.artifact_sha256, x.purpose)):
        key = (e.role.value, e.artifact_sha256, e.purpose)
        out.append(OrdinalEntry(e.role, e.artifact_sha256, e.purpose, seen[key]))
        seen[key] += 1
    return out


def build_fingerprint(entries: Iterable[ComponentEntry]) -> str:
    items = [o.as_json() for o in assign_ordinals(entries)]
    if not items:
        raise ValueError("a build needs at least one component artifact")
    items.sort(key=canonical_json)
    return canonical_hash(items)
