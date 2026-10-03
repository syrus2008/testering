"""Regression gates (spec §41, §89 ANALYSIS gates, ACC-050).

Compare a benchmark summary with a committed baseline. Tolerances are part of the
baseline file (configured, versioned). Any failing gate blocks a STABLE release.
"""

from __future__ import annotations

from typing import Any

DEFAULT_TOLERANCES = {
    "precision": 0.02,
    "recall": 0.02,
    "false_new_rate": 0.02,
    "coverage": 0.02,
    "lineage.purity": 0.05,
    "lineage.multi_version_recovery": 0.05,
}
LOWER_IS_BETTER = {"false_new_rate", "lineage.fragmentation"}


def _get(d: dict[str, Any], dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def check_gates(summary: dict[str, Any], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    tol = {**DEFAULT_TOLERANCES, **baseline.get("tolerances", {})}
    out = []
    for metric, t in sorted(tol.items()):
        base, cur = _get(baseline["summary"], metric), _get(summary, metric)
        if base is None:
            continue
        if cur is None:
            out.append({"gate": metric, "ok": False, "baseline": base, "current": None, "reason": "not measured"})
            continue
        regression = (cur - base) if metric in LOWER_IS_BETTER else (base - cur)
        out.append({"gate": metric, "ok": regression <= t, "baseline": base, "current": cur, "tolerance": t})
    return out
