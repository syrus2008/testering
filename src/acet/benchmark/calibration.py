"""Context-stratified calibration (spec §67, ACET-SCI-001/002, ACET-BEN-003/004, ACC-028/068/069/070/146/147).

A raw engine score may be shown as a probability only through a *validated*
calibration for the same engine and context, fitted on a calibration split.
Anything else is displayed as a class; a context never seen in calibration is
OUT_OF_DISTRIBUTION and may force ABSTAIN. Raw scores are never modified.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.canonical import stable_json
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso

MIN_SAMPLES = 30  # below this a mapping is stored but never validated (calibrable policy)
BINS = 10


def pav(points: list[tuple[float, bool]]) -> list[tuple[float, float, int]]:
    """Pool-adjacent-violators isotonic regression → [(upper_score, precision, n)]."""
    blocks: list[list[float]] = []  # [sum_y, n, max_x]
    for x, y in sorted(points):
        blocks.append([float(y), 1, x])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            s, n, mx = blocks.pop()
            blocks[-1][0] += s
            blocks[-1][1] += n
            blocks[-1][2] = mx
    return [(b[2], round(b[0] / b[1], 4), int(b[1])) for b in blocks]


def reliability_diagram(points: list[tuple[float, bool]], bins: int = BINS) -> list[dict[str, Any]]:
    out = []
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        sel = [y for x, y in points if lo <= x < hi or (i == bins - 1 and x == 1.0)]
        out.append(
            {
                "bin": [round(lo, 2), round(hi, 2)],
                "n": len(sel),
                "empirical_precision": round(sum(sel) / len(sel), 4) if sel else None,
            }
        )
    return out


def calibrate(ws: Workspace, benchmark_run_id: str, engine: str, *, min_samples: int = MIN_SAMPLES) -> list[str]:
    """Fit one calibration per context key present in the benchmark run (never a global one)."""
    row = ws.db.conn.execute("SELECT * FROM benchmark_run WHERE id=?", (benchmark_run_id,)).fetchone()
    if row is None:
        raise AcetError("ACET-NOTFOUND-001", f"benchmark run {benchmark_run_id}")
    if row["split"] != "calibration":
        raise AcetError("ACET-IMP-005", "calibration must be fitted on the 'calibration' split (ACET-BEN-004)")
    manifest, metrics = json.loads(row["manifest_json"]), json.loads(row["metrics_json"])
    by_ctx: dict[str, list[tuple[float, bool]]] = {}
    for e, s, ok, key in metrics["observations"]:  # each observation carries its own context (ACET-SCI-001)
        if e == engine and s is not None:
            by_ctx.setdefault(key, []).append((float(s), bool(ok)))
    ids = []
    with ws.db.transaction() as tx:
        for key, pts in sorted(by_ctx.items()):
            mapping = pav(pts)
            validated = len(pts) >= min_samples
            cid = uuid7()
            tx.execute(
                "INSERT INTO calibration_profile(id, engine, context_key, context_json, dataset_hash, split, method,"
                " mapping_json, metrics_json, validated, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    cid,
                    engine,
                    key,
                    stable_json(manifest["contexts"].get(key, {})).decode(),
                    manifest["dataset_hash"],
                    "calibration",
                    "isotonic-pav@1",
                    stable_json(mapping).decode(),
                    stable_json(
                        {"n": len(pts), "reliability": reliability_diagram(pts), "min_samples": min_samples}
                    ).decode(),
                    int(validated),
                    utc_now_iso(),
                ),
            )
            ids.append(cid)
    return ids


@dataclass(frozen=True)
class ConfidenceDisplay:
    kind: str  # "probability" | "class"
    state: str  # CALIBRATED | UNCALIBRATED | OUT_OF_DISTRIBUTION
    value: float | None
    calibration_profile_id: str | None
    abstain: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "state": self.state,
            "value": self.value,
            "calibration_profile_id": self.calibration_profile_id,
            "abstain": self.abstain,
        }


def display_confidence(
    ws: Workspace, engine: str, ctx_key: str, raw_score: float | None, *, ood_policy: str = "class"
) -> ConfidenceDisplay:
    """ood_policy: 'class' (show class, no probability) or 'abstain' (force ABSTAIN, ACC-147)."""
    rows = ws.db.conn.execute(
        "SELECT * FROM calibration_profile WHERE engine=? AND validated=1 ORDER BY created_at DESC", (engine,)
    ).fetchall()
    match = next((r for r in rows if r["context_key"] == ctx_key), None)
    if match is not None and raw_score is not None:
        mapping = json.loads(match["mapping_json"])
        p = next((prec for upper, prec, _n in mapping if raw_score <= upper), mapping[-1][1])
        return ConfidenceDisplay("probability", "CALIBRATED", p, match["id"], False)
    if rows or ws.db.conn.execute("SELECT 1 FROM calibration_profile WHERE engine=? LIMIT 1", (engine,)).fetchone():
        return ConfidenceDisplay("class", "OUT_OF_DISTRIBUTION", None, None, ood_policy == "abstain")
    return ConfidenceDisplay("class", "UNCALIBRATED", None, None, False)
