"""QBinDiff provider (spec §69: experimental, memory-gated; ACET-QBD-001/002, ACC-072).

Runs inside the Engine Pack's isolated Python (``ACET_PROVIDER_QBINDIFF`` points
to that interpreter). Before launching, a conservative gate refuses inputs whose
function counts exceed the profile's validated budget: never a deliberate OOM.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from acet.engines.proc import run_engine
from acet.engines.worker import WorkerContext

RUNNER = Path(__file__).resolve().parent / "qbindiff_runner.py"


def _function_count(binexport: Path) -> int | None:
    meta = binexport.with_name("result.json")
    try:
        return int(json.loads(meta.read_text(encoding="utf-8")).get("function_count"))
    except (OSError, ValueError, TypeError):
        return None


def gate(n_left: int | None, n_right: int | None, max_functions: int) -> str | None:
    if n_left is None or n_right is None:
        return None
    if max(n_left, n_right) > max_functions:
        return f"function count {max(n_left, n_right)} exceeds validated budget {max_functions} (ACET-QBD-001)"
    return None


def diff(ctx: WorkerContext) -> dict[str, Any]:
    lay = ctx.layout()["derived"]
    li, ri = lay.index("binexport.export@left"), lay.index("binexport.export@right")
    lmeta, rmeta = ctx.derived(li), ctx.derived(ri)
    if lmeta.get("status") != "complete" or rmeta.get("status") != "complete":
        ctx.skip("SKIPPED_INCOMPATIBLE", "BinExport input unavailable")
    lfile, rfile = ctx.derived_dir(li) / lmeta["file"], ctx.derived_dir(ri) / rmeta["file"]
    max_functions = int(ctx.config.get("max_functions", 5000))
    est = int(ctx.config.get("bytes_per_function_pair", 64))
    nl = ctx.config.get("_function_count_left")
    nr = ctx.config.get("_function_count_right")
    reason = gate(nl, nr, max_functions)
    if reason is None and nl and nr and nl * nr * est > int(ctx.config.get("max_memory_bytes", 4 * 1024**3)):
        reason = "estimated similarity matrix exceeds memory budget (ACET-QBD-001)"
    if reason:
        ctx.skip("SKIPPED_POLICY", reason)
    python = os.environ.get("ACET_PROVIDER_QBINDIFF") or sys.executable
    work = ctx.output_dir / "_work"
    work.mkdir(exist_ok=True)
    out = work / "matches.json"
    ctx.auto_heartbeat = False
    code = run_engine(
        [python, "-I", str(RUNNER), str(lfile), str(rfile), str(out)],
        cwd=work,
        heartbeat=ctx.heartbeat,
        stop_requested=ctx.stop_requested,
    )
    if code != 0 or not out.is_file():
        ctx.error(f"QBinDiff failed (exit {code})")
        shutil.rmtree(work, ignore_errors=True)
        return {
            "engine": "qbindiff",
            "engine_version": "unknown",
            "families_used": [],
            "pairs": [],
            "unmatched_left": [],
            "unmatched_right": [],
            "status": "invalid",
            "experimental": True,
        }
    raw = json.loads(out.read_text(encoding="utf-8"))
    ctx.write_output("qbindiff-matches.json", out.read_bytes())
    shutil.rmtree(work, ignore_errors=True)
    ctx.engine_version = f"qbindiff-{raw.get('version')}"
    pairs = []
    for m in raw["matches"]:
        sim, conf = float(m["similarity"]), float(m["confidence"])
        decision = (
            "STRONG" if sim >= 0.95 and conf >= 0.95 else ("PROBABLE" if sim >= 0.5 and conf >= 0.5 else "UNRESOLVED")
        )
        fams = ["cfg", "instruction"]  # features registered by the runner: WL (cfg), mnemonics (instruction)
        pairs.append(
            {
                "left": m["primary"],
                "right": m["secondary"],
                "raw_score": round(sim, 4),
                "raw_confidence": round(conf, 4),
                "decision": decision,
                "rule": None,
                "evidence": [{"family": f, "score": round(sim, 4), "supports": sim >= 0.5} for f in fams],
            }
        )
    ctx.count("pairs", len(pairs))
    return {
        "engine": "qbindiff",
        "engine_version": ctx.engine_version,
        "experimental": True,
        "families_used": ["cfg", "instruction"],
        "features": raw.get("features"),
        "pairs": pairs,
        "unmatched_left": [],
        "unmatched_right": [],
    }
