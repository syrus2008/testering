"""Ordered SQL migrations. File names: NNNN_<slug>.sql; NNNN is the schema version."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources

_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str


def load_migrations() -> list[Migration]:
    out: list[Migration] = []
    for entry in resources.files(__package__).iterdir():
        m = _NAME.match(entry.name)
        if m:
            out.append(Migration(int(m.group(1)), entry.name, entry.read_text(encoding="utf-8")))
    out.sort(key=lambda x: x.version)
    for expected, mig in enumerate(out, start=1):
        if mig.version != expected:
            raise RuntimeError(f"migration sequence gap: expected {expected:04d}, got {mig.name}")
    return out


LATEST_SCHEMA_VERSION = 1
