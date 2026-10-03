"""Result comparability (spec §86, ACET-CMP-001, ACC-093).

Two analysis runs are comparable numerically only when their feature schema,
normalizer semantics, processor versions of measuring processors and calibration
relationship agree. Otherwise COMPARABILITY is PARTIAL or NONE and numeric deltas
must not be computed between them.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from acet.application.workspace import Workspace

MEASURING = ("acet.pe", "acet.strings", "acet.hash", "acet.features", "ghidra.extract")


class Comparability(StrEnum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    NONE = "NONE"


def _signature(ws: Workspace, run_id: str) -> dict[str, Any]:
    procs = {
        r["processor_id"]: r["processor_version"]
        for r in ws.db.conn.execute(
            "SELECT DISTINCT processor_id, processor_version FROM processor_run WHERE analysis_run_id=? AND status IN"
            " ('COMPLETED','PARTIAL')",
            (run_id,),
        )
    }
    fs = {
        (r[0], r[1])
        for r in ws.db.conn.execute(
            "SELECT DISTINCT fi.feature_schema_version, fi.normalizer_version FROM function_instance fi JOIN processor_run pr"
            " ON pr.derived_result_id=fi.derived_result_id WHERE pr.analysis_run_id=?",
            (run_id,),
        )
    }
    cfg = json.loads(
        ws.db.conn.execute("SELECT resolved_config_json FROM analysis_run WHERE id=?", (run_id,)).fetchone()[0] or "{}"
    )
    return {"processors": procs, "features": fs, "profile": (cfg.get("profile") or {}).get("name")}


def comparability(ws: Workspace, run_a: str, run_b: str) -> tuple[Comparability, list[str]]:
    a, b = _signature(ws, run_a), _signature(ws, run_b)
    reasons: list[str] = []
    if a["features"] and b["features"] and a["features"] != b["features"]:
        reasons.append(f"feature schema / normalizer differ: {sorted(a['features'])} vs {sorted(b['features'])}")
    for p in MEASURING:
        va, vb = a["processors"].get(p), b["processors"].get(p)
        if va and vb and va != vb:
            reasons.append(f"{p} version {va} vs {vb}")
    if any("feature schema" in r for r in reasons):
        return Comparability.NONE, reasons
    if reasons or a["profile"] != b["profile"]:
        if a["profile"] != b["profile"]:
            reasons.append(f"profiles differ: {a['profile']} vs {b['profile']}")
        return Comparability.PARTIAL, reasons
    return Comparability.FULL, reasons


def compare_metric(
    ws: Workspace, run_a: str, run_b: str, value_a: float | None, value_b: float | None
) -> dict[str, Any]:
    """Numeric delta only when definitions are compatible; never forced (ACC-093)."""
    c, reasons = comparability(ws, run_a, run_b)
    if c is not Comparability.FULL or value_a is None or value_b is None:
        return {"comparability": c.value, "delta": None, "reasons": reasons or ["value not measured"]}
    return {"comparability": c.value, "delta": value_b - value_a, "reasons": []}
