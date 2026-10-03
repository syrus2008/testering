"""Normalized function view (spec §19; feature_schema_version=1, normalizer acet-norm@1).

Input: the Ghidra export. Output: per-function features grouped by evidence
family (identity / instruction / cfg / callgraph / data-reference). Semantic
features are not produced in V1 (MeasurementState NOT_MEASURED).
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from acet.engines.worker import WorkerContext

FEATURE_SCHEMA_VERSION = 1
NORMALIZER_VERSION = "acet-norm@1"


def _h(parts: list[str]) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _is_default_name(name: str | None, source: str | None) -> bool:
    if not name:
        return True
    return source == "DEFAULT" or name.startswith(("FUN_", "thunk_FUN_", "LAB_", "SUB_"))


def cfg_hash(blocks: list[dict[str, Any]], iterations: int = 2) -> str:
    """Weisfeiler-Lehman hash of the block graph, labels = out-degree/in-degree (address independent)."""
    starts = [b["start"] for b in blocks]
    idx = {s: i for i, s in enumerate(starts)}
    succ = [[idx[x] for x in b["succ"] if x in idx] for b in blocks]
    pred: list[list[int]] = [[] for _ in blocks]
    for i, ss in enumerate(succ):
        for j in ss:
            pred[j].append(i)
    labels = [f"{len(succ[i])}:{len(pred[i])}" for i in range(len(blocks))]
    for _ in range(iterations):
        labels = [
            hashlib.sha1(
                (labels[i] + "|" + ",".join(sorted(labels[j] for j in succ[i]))).encode(), usedforsecurity=False
            ).hexdigest()[:16]
            for i in range(len(blocks))
        ]
    return _h(sorted(labels))


def featurize(export: dict[str, Any]) -> dict[str, Any]:
    prog = export.get("program") or {}
    base = int(prog.get("image_base") or 0)
    funcs = [f for f in export.get("functions", [])]
    callers: dict[int, list[int]] = {}
    for f in funcs:
        for c in f.get("calls", []):
            callers.setdefault(c, []).append(f["entry"])
    names = {f["entry"]: f["name"] for f in funcs if not _is_default_name(f["name"], f.get("name_source"))}
    out = []
    for f in funcs:
        insns = [f"{m} {o}".strip() for m, o in f.get("insns", [])]
        mnems = [m for m, _ in f.get("insns", [])]
        blocks = f.get("blocks", [])
        edges = sum(len(b.get("succ", [])) for b in blocks)
        named = not _is_default_name(f["name"], f.get("name_source"))
        consts = sorted(set(f.get("constants", [])))
        out.append(
            {
                "entry": f["entry"],
                "rva": f["entry"] - base,
                "size": f["size"],
                "thunk": f.get("thunk", False),
                "section": f.get("section"),
                "identity": {"name": f["name"] if named else None, "name_source": f.get("name_source")},
                "instruction": {
                    "count": len(insns),
                    "mnemonics": dict(sorted(Counter(mnems).items())),
                    "normalized_hash": _h(insns) if insns else None,
                    "mnemonic_hash": _h(mnems) if mnems else None,
                },
                "cfg": {
                    "blocks": len(blocks),
                    "edges": edges,
                    "cyclomatic": max(1, edges - len(blocks) + 2),
                    "hash": cfg_hash(blocks) if blocks else None,
                },
                "callgraph": {
                    "callees": sorted(f.get("calls", [])),
                    "callers": sorted(callers.get(f["entry"], [])),
                    "callee_names": sorted(names[c] for c in f.get("calls", []) if c in names),
                    "imports": sorted(f.get("imports", [])),
                },
                "data": {"strings": sorted(set(f.get("strings", []))), "constants": consts},
                "semantic": {"state": "NOT_MEASURED"},
            }
        )
    exec_size = sum(b["size"] for b in prog.get("blocks", []) if b.get("execute"))
    covered = sum(f["size"] for f in funcs)
    quality_ratio = round(min(1.0, covered / exec_size), 4) if exec_size else None
    return {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "normalizer_version": NORMALIZER_VERSION,
        "image_base": base,
        "engine_version": export.get("engine_version"),
        "function_count": len(out),
        "extraction_quality": {
            "state": "MEASURED" if quality_ratio is not None else "NOT_MEASURED",
            "code_coverage_ratio": quality_ratio,
            "error_bookmarks": prog.get("error_bookmarks"),
            "export_status": export.get("status"),
        },
        "functions": sorted(out, key=lambda x: x["entry"]),
    }


def normalized_view(ctx: WorkerContext) -> dict[str, Any]:
    export = ctx.derived(0)
    if export.get("status") != "complete":
        ctx.error("upstream extraction is not complete")
    res = featurize(export)
    ctx.count("functions", res["function_count"])
    return res
