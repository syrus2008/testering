"""Provider quirks / Known Limitations Registry (spec §68, §84, ACET-ENG-003/004, ACC-073/074).

Versioned data, not code paths: log rules validate provider completion; known
limitations turn recognised provider failures into SKIPPED_KNOWN_LIMITATION /
FAILED_PROVIDER instead of a conclusion about the binary.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any

from acet.jobs.completion import CompletionState, LogRule

REGISTRY_VERSION = 1

LOG_RULES: dict[str, list[LogRule]] = {
    "ghidra": [
        LogRule(
            "GHD-LOG-001",
            r"(?m)^\s*ERROR .*(Analysis failed|Exception)",
            CompletionState.PARTIAL,
            "Ghidra reported an internal analysis error despite a successful exit (ACC-053)",
        ),
        LogRule(
            "GHD-LOG-002",
            r"(?i)analysis timed out|Analysis timeout",
            CompletionState.PARTIAL,
            "Ghidra native analysis timeout (ACET-GHD-005)",
        ),
        LogRule("GHD-LOG-003", r"java\.lang\.OutOfMemoryError", CompletionState.INVALID, "Ghidra JVM out of memory"),
    ],
    "ghidriff": [
        LogRule(
            "GDF-LOG-001",
            r"Traceback \(most recent call last\)",
            CompletionState.PARTIAL,
            "ghidriff raised a Python exception",
        ),
    ],
    "bindiff": [
        LogRule("BDF-LOG-001", r"(?i)error: .*", CompletionState.PARTIAL, "BinDiff reported an error"),
    ],
    "binexport": [
        LogRule("BEX-LOG-001", r"(?i)BinExport.*(failed|error)", CompletionState.PARTIAL, "BinExport export error"),
    ],
    "qbindiff": [
        LogRule("QBD-LOG-001", r"MemoryError", CompletionState.INVALID, "QBinDiff ran out of memory"),
    ],
}


def log_rules_for(provider_or_processor: str) -> list[LogRule]:
    return LOG_RULES.get(provider_or_processor, [])


@dataclass(frozen=True)
class KnownLimitation:
    id: str
    provider_id: str
    provider_version_range: str
    input_context: dict[str, Any]
    symptom: str
    severity: str
    workaround: str
    source: str
    status: str
    symptom_regex: str | None = None

    def matches_version(self, version: str | None) -> bool:
        if self.provider_version_range in ("*", "") or version is None:
            return True
        return _in_range(version, self.provider_version_range)

    def matches_log(self, text: str) -> bool:
        return bool(self.symptom_regex and re.search(self.symptom_regex, text))


def _vt(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _in_range(version: str, spec: str) -> bool:
    ok = True
    for part in spec.split(","):
        part = part.strip()
        m = re.match(r"(>=|<=|<|>|==)\s*(.+)", part)
        if not m:
            continue
        op, ref = m.groups()
        a, b = _vt(version), _vt(ref)
        ok &= {">=": a >= b, "<=": a <= b, "<": a < b, ">": a > b, "==": a == b}[op]
    return ok


def load_known_limitations() -> list[KnownLimitation]:
    raw = json.loads((resources.files("acet.engines") / "known_limitations.json").read_text(encoding="utf-8"))
    from acet.domain.jsonschema import validate_named

    out = []
    for item in raw["limitations"]:
        validate_named({k: v for k, v in item.items() if k != "symptom_regex"}, "known-limitation")
        out.append(KnownLimitation(**item))
    return out


def applicable_limitations(provider_id: str, version: str | None) -> list[KnownLimitation]:
    return [k for k in load_known_limitations() if k.provider_id == provider_id and k.matches_version(version)]
