"""Benchmark metrics (spec §39, ACET-BEN-002): pairs, false-new, coverage, lineage quality."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from acet.application.workspace import Workspace

JOIN = ("EXACT", "STRONG", "PROBABLE")


def _prf(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return {
        "precision": None if p is None else round(p, 4),
        "recall": None if r is None else round(r, 4),
        "f1": None if f is None else round(f, 4),
    }


def evaluate_transition(
    ws: Workspace,
    run_id: str,
    lsha: str,
    rsha: str,
    t: dict[str, Any],
    gt_left: dict[str, int],
    features_left: set[int],
    features_right: set[int],
) -> tuple[dict[str, Any], list[tuple[str, float | None, bool]]]:
    required = {(p["left"], p["right"]) for p in t["pairs"]}
    acceptable = set(required)
    acceptable |= {(s["left"], r) for s in t["splits"] for r in s["rights"]}
    acceptable |= {(x, m["right"]) for m in t["merges"] for x in m["lefts"]}
    known_left = set(gt_left.values())
    rows = ws.db.conn.execute(
        "SELECT decision, evidence_json FROM consensus_match WHERE analysis_run_id=? AND"
        " left_artifact_sha256=? AND right_artifact_sha256=?",
        (run_id, lsha, rsha),
    ).fetchall()
    predicted: set[tuple[int, int]] = set()
    by_class: dict[str, list[bool]] = defaultdict(list)
    right_only: set[int] = set()
    for r in rows:
        ev = json.loads(r["evidence_json"])
        la, ra = ev.get("left_address"), ev.get("right_address")
        if ev.get("side") == "right-only":
            right_only.add(ra)
            continue
        if la not in known_left or ra is None or r["decision"] not in JOIN:
            continue
        predicted.add((la, ra))
        by_class[r["decision"]].append((la, ra) in acceptable)
    tp = len(predicted & acceptable)
    fp = len(predicted - acceptable)
    fn = len(required - predicted)
    extracted_required = {p for p in required if p[0] in features_left and p[1] in features_right}
    false_new = sum(1 for (_l, r) in extracted_required if r in right_only)
    gt_fns = set(gt_left.values())
    m: dict[str, Any] = {
        **_prf(tp, fp, fn),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "coverage": round(len(gt_fns & features_left) / len(gt_fns), 4) if gt_fns else None,
        "false_new": false_new,
        "false_new_rate": round(false_new / len(extracted_required), 4) if extracted_required else None,
        "precision_by_class": {k: round(sum(v) / len(v), 4) for k, v in sorted(by_class.items())},
    }
    # matcher-level observations (engine, raw score, correct) for calibration
    obs: list[tuple[str, float | None, bool]] = []
    for r in ws.db.conn.execute(
        "SELECT engine, raw_score, evidence_json FROM matcher_result WHERE analysis_run_id=? AND"
        " left_artifact_sha256=? AND right_artifact_sha256=?",
        (run_id, lsha, rsha),
    ):
        ev = json.loads(r["evidence_json"])
        if ev.get("left") in known_left:
            obs.append((r["engine"], r["raw_score"], (ev.get("left"), ev.get("right")) in acceptable))
    return m, obs


def logical_ids(gt: dict[str, Any], comp: str) -> dict[tuple[str, int], int]:
    """Union-find over GT relations (pairs, splits, merges): (version, address) → logical id."""
    parent: dict[tuple[str, int], tuple[str, int]] = {}

    def find(x: tuple[str, int]) -> tuple[str, int]:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: tuple[str, int], b: tuple[str, int]) -> None:
        parent[find(a)] = find(b)

    for v, fs in gt["functions"][comp].items():
        for addr in fs.values():
            find((v, addr))
    for t in gt["transitions"]:
        if t["component"] != comp:
            continue
        a, b = t["from"], t["to"]
        for p in t["pairs"]:
            union((a, p["left"]), (b, p["right"]))
        for s in t["splits"]:
            for r in s["rights"]:
                union((a, s["left"]), (b, r))
        for m in t["merges"]:
            for x in m["lefts"]:
                union((a, x), (b, m["right"]))
    roots: dict[tuple[str, int], int] = {}
    return {k: roots.setdefault(find(k), len(roots)) for k in list(parent)}


def lineage_metrics(
    ws: Workspace, lineage_run: str, gt: dict[str, Any], sha_to: dict[str, tuple[str, str]]
) -> dict[str, Any]:
    """sha_to: artifact sha → (component, version)."""
    ids = {comp: logical_ids(gt, comp) for comp in gt["components"]}
    members: dict[str, set[int]] = defaultdict(set)
    lineages_of: dict[tuple[str, int], set[str]] = defaultdict(set)
    rows = ws.db.conn.execute(
        "SELECT la.lineage_id, la.relation, fi.artifact_sha256, fi.address FROM lineage_assignment la JOIN"
        " function_instance fi ON fi.id=la.function_instance_id WHERE la.analysis_run_id=?",
        (lineage_run,),
    ).fetchall()
    for r in rows:
        if r["relation"] == "DISAPPEARED" or r["artifact_sha256"] not in sha_to:
            continue
        comp, ver = sha_to[r["artifact_sha256"]]
        lid = ids[comp].get((ver, int(r["address"])))
        if lid is None:
            continue
        members[r["lineage_id"]].add(lid)
        lineages_of[(comp, lid)].add(r["lineage_id"])
    impure = [k for k, v in members.items() if len(v) > 1]
    fragmented = [k for k, v in lineages_of.items() if len(v) > 1]
    versions = gt["versions"]
    full_chain = 0
    recovered = 0
    for comp in gt["components"]:
        by_logical: dict[int, set[str]] = defaultdict(set)
        for (v, _a), lid in ids[comp].items():
            by_logical[lid].add(v)
        for lid, vs in by_logical.items():
            if len(vs) == len(versions):
                full_chain += 1
                if len(lineages_of.get((comp, lid), set())) == 1:
                    recovered += 1
    return {
        "lineages": len(members),
        "purity": round(1 - len(impure) / len(members), 4) if members else None,
        "wrong_merge": len(impure),
        "fragmentation": round(len(fragmented) / len(lineages_of), 4) if lineages_of else None,
        "wrong_split": len(fragmented),
        "multi_version_recovery": round(recovered / full_chain, 4) if full_chain else None,
    }
