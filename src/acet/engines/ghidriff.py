"""Ghidriff provider (spec §17: primary patch diff) + MatcherNormalizer to the ACET matcher DTO.

Ghidriff correlator names are mapped to evidence families. The mapping is a
versioned part of this adapter (``ghidriff-map@1``); unknown correlators map
to no family (never assumed supportive).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from typing import Any

from acet.engines.proc import run_engine
from acet.engines.worker import WorkerContext

MAPPING_VERSION = "ghidriff-map@1"
# correlator -> (families, engine decision)
CORRELATORS: dict[str, tuple[tuple[str, ...], str]] = {
    "ExactBytesFunctionHasher": (("instruction",), "EXACT"),
    "ExactInstructionsFunctionHasher": (("instruction",), "STRONG"),
    "ExactMnemonicsFunctionHasher": (("instruction",), "STRONG"),
    "BulkBasicBlockMnemonicHash": (("instruction", "cfg"), "PROBABLE"),
    "StructuralGraphExactHash": (("cfg",), "PROBABLE"),
    "StructuralGraphHash": (("cfg",), "PROBABLE"),
    "SigCallingCalledHasher": (("callgraph",), "PROBABLE"),
    "Implied Match": (("callgraph",), "PROBABLE"),
    "Decomp Match": (("instruction",), "PROBABLE"),
    "SymbolsHash": (("identity",), "STRONG"),
    "NamespaceNameSigHasher": (("identity",), "STRONG"),
    "StringsRefsHasher": (("data-reference",), "PROBABLE"),
}
RANK = {"EXACT": 3, "STRONG": 2, "PROBABLE": 1}


def _addr(x: str | int) -> int:
    return x if isinstance(x, int) else int(str(x), 16)


def _default(name: str | None) -> bool:
    return not name or name.startswith(("FUN_", "thunk_FUN_"))


def normalize(diff: dict[str, Any], matches: dict[str, Any], engine_version: str | None) -> dict[str, Any]:
    modified = {_addr(m["old"]["address"]): m for m in diff["functions"].get("modified", [])}
    names_l: dict[int, str] = {}
    for m in modified.values():
        names_l[_addr(m["old"]["address"])] = m["old"]["name"]
    pairs = []
    for left_hex, cands in sorted(matches.get("address_matches", {}).items(), key=lambda kv: _addr(kv[0])):
        left = _addr(left_hex)
        if not cands:
            continue
        right_hex, types = cands[0]
        fams: set[str] = set()
        decision = None
        unknown = []
        for t in types:
            if t not in CORRELATORS:
                unknown.append(t)
                continue
            f, d = CORRELATORS[t]
            if "identity" in f and left in names_l and _default(names_l[left]):
                continue  # default (address-derived) names are not identity evidence
            fams |= set(f)
            decision = d if decision is None or RANK[d] > RANK[decision] else decision
        m = modified.get(left)
        raw = float(m["ratio"]) if m is not None else 1.0
        if m is not None and decision == "EXACT":
            decision = "STRONG"  # modified functions are never byte-identical
        if decision is None:
            decision = "UNRESOLVED"
        evidence = [{"family": f, "score": raw, "supports": True} for f in sorted(fams)]
        pairs.append(
            {
                "left": left,
                "right": _addr(right_hex),
                "raw_score": round(raw, 4),
                "decision": decision,
                "rule": "exact-bytes" if decision == "EXACT" else None,
                "evidence": evidence,
                "correlators": types,
                "unknown_correlators": unknown,
                "ratios": None if m is None else {k: m.get(k) for k in ("ratio", "i_ratio", "m_ratio", "b_ratio")},
                "alternatives": [[_addr(c[0]), None] for c in cands[1:3]],
            }
        )
    return {
        "engine": "ghidriff",
        "engine_version": engine_version or "unknown",
        "mapping": MAPPING_VERSION,
        "families_used": sorted({f for fs, _ in CORRELATORS.values() for f in fs}),
        "pairs": pairs,
        "unmatched_left": [
            {"left": _addr(f["address"]), "candidates": []} for f in diff["functions"].get("deleted", [])
        ],
        "unmatched_right": [
            {"right": _addr(f["address"]), "candidates": []} for f in diff["functions"].get("added", [])
        ],
        "stats": diff.get("stats"),
    }


def diff(ctx: WorkerContext) -> dict[str, Any]:
    left, right = ctx.artifact_path(0), ctx.artifact_path(1)
    work = ctx.output_dir / "_work"
    (work / "in").mkdir(parents=True, exist_ok=True)
    # ghidriff names outputs after file names: give both sides distinct names (bytes untouched).
    lcopy, rcopy = work / "in" / f"left_{left.name}", work / "in" / f"right_{right.name}"
    shutil.copyfile(left, lcopy)
    shutil.copyfile(right, rcopy)
    env = dict(os.environ)
    env["GHIDRA_INSTALL_DIR"] = os.environ.get("ACET_GHIDRA_DIR", env.get("GHIDRA_INSTALL_DIR", ""))
    ctx.engine_version = f"ghidriff-{os.environ.get('ACET_PROVIDER_GHIDRIFF_VERSION') or 'unknown'}"
    argv = [
        os.environ.get("ACET_PROVIDER_GHIDRIFF") or sys.executable,
        "-m",
        "ghidriff",
        str(lcopy),
        str(rcopy),
        "-o",
        str(work / "out"),
        "-p",
        str(work / "proj"),
        "--max-section-funcs",
        str(int(ctx.config.get("max_section_funcs", 200))),
    ]
    ctx.auto_heartbeat = False
    code = run_engine(argv, cwd=work, heartbeat=ctx.heartbeat, stop_requested=ctx.stop_requested, env=env)
    if code != 0:
        ctx.error(f"ghidriff exit code {code}")
    jdir = work / "out" / "json"
    diffs = sorted(p for p in jdir.glob("*.ghidriff.json")) if jdir.is_dir() else []
    mfiles = sorted(p for p in jdir.glob("*.ghidriff.matches.json")) if jdir.is_dir() else []
    if not diffs or not mfiles:
        ctx.error("ghidriff produced no JSON output")
        shutil.rmtree(work, ignore_errors=True)
        return {
            "engine": "ghidriff",
            "engine_version": ctx.engine_version,
            "families_used": [],
            "pairs": [],
            "unmatched_left": [],
            "unmatched_right": [],
            "status": "invalid",
        }
    d = json.loads(diffs[0].read_text(encoding="utf-8"))
    m = json.loads(mfiles[0].read_text(encoding="utf-8"))
    md = sorted((work / "out").glob("*.ghidriff.md"))
    if md:
        ctx.write_output("ghidriff.md", md[0].read_bytes())  # raw provider report kept (ACET-MAT-003)
    shutil.rmtree(work, ignore_errors=True)
    res = normalize(d, m, ctx.engine_version)
    if res["pairs"] and any(p["unknown_correlators"] for p in res["pairs"]):
        ctx.warn("ghidriff produced correlators unknown to mapping " + MAPPING_VERSION)
    ctx.count("pairs", len(res["pairs"]))
    return res
