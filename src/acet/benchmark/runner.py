"""Benchmark runner (spec §39–41, §117, ACET-BEN-001..006, ACC-027/133/134).

Blind: the detector only receives build artifacts; ground truth is read after
analysis by the evaluator. Splits separate calibration from final evaluation.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import acet
from acet.analysis.orchestrator import compare_builds
from acet.analysis.results import derived_for_artifact
from acet.application.products import create_product
from acet.application.workspace import Workspace
from acet.benchmark.context import analysis_context, context_key
from acet.benchmark.dataset import dataset_hash, load_ground_truth, register_dataset
from acet.benchmark.metrics import evaluate_transition, lineage_metrics
from acet.domain.canonical import canonical_hash, stable_json
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso
from acet.engines.environment import EngineEnvironment, detect
from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build
from acet.lineage.builder import build_lineage
from acet.storage import repositories as repo

SPLITS = ("all", "calibration", "test")


def split_transitions(transitions: list[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    """BEN-004/005: deterministic partition grouped by version step (close versions stay together)."""
    if split == "all":
        return transitions
    steps = sorted({(t["from"], t["to"]) for t in transitions})
    keep = {s for i, s in enumerate(steps) if (i % 2 == 0) == (split == "calibration")}
    return [t for t in transitions if (t["from"], t["to"]) in keep]


def run_benchmark(
    ws: Workspace,
    root: Path,
    profile_ref: str = "STANDARD@1",
    *,
    split: str = "all",
    env: EngineEnvironment | None = None,
) -> dict[str, Any]:
    if split not in SPLITS:
        raise AcetError("ACET-IMP-005", f"split must be one of {SPLITS}")
    t0 = time.monotonic()
    did = register_dataset(ws, root)
    ds, gt = load_ground_truth(ws, did)
    env = env or detect()
    pname = f"benchmark:{ds['name']}@{ds['version']}"
    prod = repo.find_product(ws.db.conn, pname)
    product_id = prod["id"] if prod else create_product(ws, pname, vendor="ACET benchmark")
    builds: dict[str, str] = {}
    sha_to: dict[str, tuple[str, str]] = {}
    for i, v in enumerate(gt["versions"]):
        res = import_build(
            ws,
            ImportRequest(
                [root / "builds" / v],
                product_id,
                release_label=v,
                observed_at=f"2000-01-{i + 1:02d}",
                source_label=f"benchmark {v}",
                on_duplicate=DuplicatePolicy.ADD_OBSERVATION,
            ),
        )
        builds[v] = res.build_id
        for f in res.files:
            sha_to[f["sha256"]] = (f["name"], v)
    transitions = split_transitions(gt["transitions"], split)
    steps = sorted({(t["from"], t["to"]) for t in transitions}, key=lambda s: gt["versions"].index(s[0]))
    runs: dict[tuple[str, str], str] = {}
    cache_hits = 0
    for a, b in steps:
        s = compare_builds(ws, builds[a], builds[b], profile_ref, env=env)
        runs[(a, b)] = s.run_id
        cache_hits += s.cache_hits
    lin = (
        build_lineage(ws, product_id, [builds[v] for v in gt["versions"]], incremental=False)
        if split == "all"
        else None
    )
    per: list[dict[str, Any]] = []
    observations: list[tuple[str, float | None, bool, str]] = []
    contexts: dict[str, dict[str, Any]] = {}
    shas = {(comp, v): sha for sha, (comp, v) in sha_to.items()}
    for t in transitions:
        lsha, rsha = shas[(t["component"], t["from"])], shas[(t["component"], t["to"])]
        lf = derived_for_artifact(ws, "acet.features", lsha)
        rf = derived_for_artifact(ws, "acet.features", rsha)
        fl = {f["entry"] for f in (lf or {}).get("functions", [])}
        fr = {f["entry"] for f in (rf or {}).get("functions", [])}
        m, obs = evaluate_transition(
            ws, runs[(t["from"], t["to"])], lsha, rsha, t, gt["functions"][t["component"]][t["from"]], fl, fr
        )
        ctx = analysis_context(
            derived_for_artifact(ws, "acet.pe", lsha),
            lf,
            ws.db.conn.execute("SELECT size_bytes FROM artifact WHERE sha256=?", (lsha,)).fetchone()[0],
            derived_for_artifact(ws, "ghidra.extract", lsha),
        )
        contexts[context_key(ctx)] = ctx
        per.append(
            {"component": t["component"], "from": t["from"], "to": t["to"], "context_key": context_key(ctx), **m}
        )
        observations += [(e, s, ok, context_key(ctx)) for e, s, ok in obs]
    totals = {k: sum(p[k] for p in per) for k in ("tp", "fp", "fn", "false_new")}
    from acet.benchmark.metrics import _prf

    summary: dict[str, Any] = {
        **_prf(totals["tp"], totals["fp"], totals["fn"]),
        **totals,
        "coverage": round(sum(p["coverage"] or 0 for p in per) / len(per), 4) if per else None,
        "false_new_rate": round(totals["false_new"] / max(1, totals["tp"] + totals["fn"]), 4),
    }
    if lin is not None:
        summary["lineage"] = lineage_metrics(ws, lin.run_id, gt, sha_to)
    summary["performance"] = {"wall_s": round(time.monotonic() - t0, 2), "cache_hits": cache_hits}
    manifest = {
        "dataset": ds["name"],
        "dataset_version": ds["version"],
        "dataset_hash": dataset_hash(root),
        "ground_truth_sha256": canonical_hash(gt),
        "license": ds["license"],
        "split": split,
        "transitions": [[t["component"], t["from"], t["to"]] for t in transitions],
        "profile": profile_ref,
        "engines": env.manifest(),
        "acet_version": acet.__version__,
        "seed": None,
        "labels_provided_to_detector": False,
        "contexts": contexts,
        "compare_runs": {f"{a}->{b}": r for (a, b), r in runs.items()},
        "lineage_run": lin.run_id if lin else None,
    }
    bid = uuid7()
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO benchmark_run(id, dataset_id, profile_ref, split, manifest_json, metrics_json, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (
                bid,
                did,
                profile_ref,
                split,
                stable_json(manifest).decode(),
                stable_json(
                    {"summary": summary, "per_transition": per, "observations": [list(o) for o in observations]}
                ).decode(),
                utc_now_iso(),
            ),
        )
        repo.audit(tx, "benchmark.run", "benchmark_run", bid, {"split": split})
    return {"benchmark_run_id": bid, "manifest": manifest, "summary": summary, "per_transition": per}
