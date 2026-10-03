"""BinExport + BinDiff providers (spec §17, §70: ACET-BDF-001..003).

``binexport.export`` runs Ghidra headless with the BinExport extension (via the
AcetBinExport post-script). ``bindiff.diff`` runs the BinDiff CLI on two
exports and normalizes its SQLite result into the ACET matcher DTO. Raw
provider outputs (.BinExport, .BinDiff) are kept as derived files (ACET-MAT-003).
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from acet.engines.ghidra import run_headless
from acet.engines.proc import run_engine
from acet.engines.quirks import applicable_limitations
from acet.engines.worker import WorkerContext

MAPPING_VERSION = "bindiff-map@1"
# algorithm name fragment -> evidence families
ALGO_FAMILIES: list[tuple[str, tuple[str, ...]]] = [
    ("name hash", ("identity",)),
    ("manual", ("identity",)),
    ("prime signature", ("instruction",)),
    ("instruction count", ("instruction",)),
    ("hash matching", ("instruction",)),
    ("flowgraph md index", ("cfg",)),
    ("relaxed md index", ("cfg",)),
    ("loop count", ("cfg",)),
    ("callgraph md index", ("callgraph",)),
    ("call sequence", ("callgraph",)),
    ("call reference", ("callgraph",)),
    ("string references", ("data-reference",)),
    ("address sequence", ()),  # positional heuristic: no evidence family
]
MAX_FUNCTIONS_DEFAULT = 200_000  # ACET-BDF-003: refuse inputs likely to exceed provider limits (calibrable)


def families_for(algo: str) -> tuple[str, ...]:
    a = algo.lower()
    for frag, fams in ALGO_FAMILIES:
        if frag in a:
            return fams
    return ()


def export(ctx: WorkerContext) -> dict[str, Any]:
    binary = ctx.artifact_path(0)
    work = ctx.output_dir / "_work"
    work.mkdir(exist_ok=True)
    out = work / "export.BinExport"
    code, log_errors = run_headless(ctx, binary, post_scripts=[("AcetBinExport.java", [str(out)])], work=work)
    if code != 0 or not out.is_file():
        _known_limitation(ctx, "binexport", work)
        ctx.error(f"BinExport failed (exit {code})")
        shutil.rmtree(work, ignore_errors=True)
        return {"status": "invalid"}
    ctx.write_output("export.BinExport", out.read_bytes())
    shutil.rmtree(work, ignore_errors=True)
    if log_errors:
        ctx.warn(f"Ghidra log contains {log_errors} ERROR line(s)")
    return {
        "status": "complete",
        "file": "export.BinExport",
        "engine_version": ctx.engine_version,
        "size_bytes": (ctx.output_dir / "export.BinExport").stat().st_size,
    }


def _known_limitation(ctx: WorkerContext, provider: str, work: Path) -> None:
    text = ""
    for p in work.glob("**/*.log"):
        text += p.read_text(encoding="utf-8", errors="replace")
    for kl in applicable_limitations(provider, None):
        if kl.matches_log(text):
            ctx.skip("SKIPPED_KNOWN_LIMITATION", kl.symptom, kl.id)


def normalize(db_path: Path, engine_version: str) -> dict[str, Any]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        algos = dict(con.execute("SELECT id, name FROM functionalgorithm").fetchall())
        rows = con.execute(
            "SELECT address1, address2, similarity, confidence, algorithm, basicblocks, edges,"
            " instructions FROM function ORDER BY address1"
        ).fetchall()
        meta = con.execute("SELECT similarity, confidence FROM metadata").fetchone()
    finally:
        con.close()
    pairs = []
    for a1, a2, sim, conf, algo, bbs, edges, insns in rows:
        name = algos.get(algo, str(algo))
        fams = families_for(name)
        if "hash matching" in name and "name" not in name and sim >= 0.999:
            decision = "EXACT"
        elif sim >= 0.9 and conf >= 0.9:
            decision = "STRONG"
        elif sim >= 0.5 and conf >= 0.5:
            decision = "PROBABLE"
        else:
            decision = "UNRESOLVED"
        pairs.append(
            {
                "left": int(a1),
                "right": int(a2),
                "raw_score": round(float(sim), 4),
                "raw_confidence": round(float(conf), 4),
                "decision": decision,
                "rule": "bindiff-hash" if decision == "EXACT" else None,
                "algorithm": name,
                "evidence": [{"family": f, "score": round(float(sim), 4), "supports": sim >= 0.5} for f in fams],
                "matched_structure": {"basic_blocks": bbs, "edges": edges, "instructions": insns},
            }
        )
    return {
        "engine": "bindiff",
        "engine_version": engine_version,
        "mapping": MAPPING_VERSION,
        "families_used": sorted({f for _, fs in ALGO_FAMILIES for f in fs}),
        "pairs": pairs,
        "unmatched_left": [],
        "unmatched_right": [],
        "global": None if meta is None else {"similarity": meta[0], "confidence": meta[1]},
    }


def diff(ctx: WorkerContext) -> dict[str, Any]:
    lay = ctx.layout()["derived"]
    li, ri = lay.index("binexport.export@left"), lay.index("binexport.export@right")
    lmeta, rmeta = ctx.derived(li), ctx.derived(ri)
    if lmeta.get("status") != "complete" or rmeta.get("status") != "complete":
        ctx.skip("SKIPPED_INCOMPATIBLE", "BinExport input unavailable")
    lfile, rfile = ctx.derived_dir(li) / lmeta["file"], ctx.derived_dir(ri) / rmeta["file"]
    limit = int(ctx.config.get("max_bytes", 512 * 1024 * 1024))
    if lfile.stat().st_size + rfile.stat().st_size > limit:
        ctx.skip("SKIPPED_POLICY", "inputs exceed configured BinDiff size limit (ACET-BDF-003)")
    work = ctx.output_dir / "_work"
    work.mkdir(exist_ok=True)
    exe = os.environ.get("ACET_PROVIDER_BINDIFF") or "bindiff"
    version_line: list[str] = []
    ctx.auto_heartbeat = False
    code = run_engine(
        [exe, "--primary", str(lfile), "--secondary", str(rfile), "--output_dir", str(work)],
        cwd=work,
        heartbeat=ctx.heartbeat,
        stop_requested=ctx.stop_requested,
        on_line=lambda ln: version_line.append(ln) if ln.startswith("BinDiff") else None,
    )
    ctx.engine_version = (
        re.match(r"BinDiff\s+(\S+)", version_line[0]).group(1)  # type: ignore[union-attr]
        if version_line and re.match(r"BinDiff\s+(\S+)", version_line[0])
        else "bindiff"
    )
    results = sorted(work.glob("*.BinDiff"))
    if code != 0 or not results:
        _known_limitation(ctx, "bindiff", work)
        ctx.error(f"BinDiff failed (exit {code})")
        shutil.rmtree(work, ignore_errors=True)
        return {
            "engine": "bindiff",
            "engine_version": ctx.engine_version,
            "families_used": [],
            "pairs": [],
            "unmatched_left": [],
            "unmatched_right": [],
            "status": "invalid",
        }
    ctx.write_output("result.BinDiff", results[0].read_bytes())
    shutil.rmtree(work, ignore_errors=True)
    res = normalize(ctx.output_dir / "result.BinDiff", f"bindiff-{ctx.engine_version}")
    ctx.count("pairs", len(res["pairs"]))
    return res
