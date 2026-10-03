"""Golden functional self-test (spec §29, §38; ACC-002/026/100).

Runs in a throw-away workspace on the bundled demo dataset and checks the expected,
deterministic results: FAST facts always; with a live Ghidra, the STANDARD run must reproduce
the recorded golden extraction (D1: same functions, same normalized instructions) and the
golden consensus.

Verdict: ``VERIFIED`` only when every check ran against live engines and passed;
``PARTIAL`` when nothing failed but the engine checks were skipped or served by the golden
replay provider (which only proves ACET's own pipeline, not the installed engines);
``FAILED`` otherwise. ``ok`` means "no check failed" and is kept for callers that only
need that.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import tempfile
import time
from importlib import resources
from pathlib import Path
from typing import Any

EXPECTED_SHA_V1_CORE = "52c429bbf5e77c79e5bdf39868fb20084694579ca800dbb2895fdf7292d0ab5e"


def demo_dataset() -> Path | None:
    candidates = [Path(__file__).resolve().parents[3] / "datasets" / "demo"]
    with contextlib.suppress(ModuleNotFoundError, TypeError):
        candidates.append(Path(str(resources.files("acet"))) / "demo")
    return next((c for c in candidates if (c / "ground_truth.json").is_file()), None)


def run_self_test(*, standard: bool = True, env: Any = None) -> dict[str, Any]:
    """``env``: the engine environment to verify (default: local detection; the Engine Pack Manager passes
    the environment of the pack it is installing or verifying)."""
    from acet.analysis.orchestrator import analyze_build, compare_builds
    from acet.analysis.results import derived_for_artifact
    from acet.application.products import create_product
    from acet.application.workspace import create_workspace
    from acet.engines.environment import detect
    from acet.ingest.importer import ImportRequest, import_build

    t0 = time.monotonic()
    demo = demo_dataset()
    checks: list[dict[str, Any]] = []
    if demo is None:
        return {
            "ok": False,
            "verdict": "FAILED",
            "engine_mode": "none",
            "checks": [{"name": "demo dataset", "ok": False, "detail": "not found"}],
        }
    engine_mode = "none"
    tmp = Path(tempfile.mkdtemp(prefix="acet-selftest-"))
    try:
        ws = create_workspace("self-test", tmp)
        try:
            pid = create_product(ws, "Self-test (Fictional Guard)")
            b1 = import_build(ws, ImportRequest([demo / "builds" / "v1"], pid)).build_id
            checks.append(
                {
                    "name": "import",
                    "ok": EXPECTED_SHA_V1_CORE in {r[0] for r in ws.db.conn.execute("SELECT sha256 FROM artifact")},
                }
            )
            s = analyze_build(ws, b1, "FAST@1")
            pe = derived_for_artifact(ws, "acet.pe", EXPECTED_SHA_V1_CORE) or {}
            exports = {e["name"] for e in ((pe.get("exports") or {}).get("value") or {}).get("symbols", [])}
            checks.append(
                {"name": "FAST facts", "ok": s.status == "COMPLETED" and {"GuardInit", "GuardScan"} <= exports}
            )
            env = env or detect()
            if env.available("ghidra"):
                engine_mode = "replay" if env.providers["ghidra"].extra.get("replay") else "live"
            if standard and env.available("ghidra"):
                b2 = import_build(ws, ImportRequest([demo / "builds" / "v2"], pid)).build_id
                c = compare_builds(ws, b1, b2, "STANDARD@1", env=env)
                gt = json.loads((demo / "ground_truth.json").read_text(encoding="utf-8"))
                left = gt["functions"]["guardcore.dll"]["v1"]["xor_obfuscate"]
                right = gt["functions"]["guardcore.dll"]["v2"]["obfuscate_buffer"]
                ok = any(
                    json.loads(r[1]).get("left_address") == left
                    and json.loads(r[1]).get("right_address") == right
                    and r[0] == "EXACT"
                    for r in ws.db.conn.execute(
                        "SELECT decision, evidence_json FROM consensus_match WHERE analysis_run_id=?", (c.run_id,)
                    )
                )
                check: dict[str, Any] = {
                    "name": "STANDARD golden consensus",
                    "ok": ok and c.status.startswith("COMPLETED"),
                    "detail": f"{c.status}; engine={env.providers['ghidra'].version}",
                }
                if not check["ok"]:  # the throw-away workspace is deleted below: keep why it failed
                    check["diagnostics"] = _failure_diagnostics(ws, c.run_id, c.missing_evidence)
                checks.append(check)
                if engine_mode == "live":
                    checks.append(_golden_extraction_check(ws, demo))
                else:
                    checks.append(
                        {
                            "name": "golden Ghidra extraction",
                            "ok": None,
                            "detail": "golden replay provider: installed engines not exercised",
                        }
                    )
            else:
                checks.append(
                    {"name": "STANDARD golden consensus", "ok": None, "detail": "Ghidra unavailable: skipped"}
                )
        finally:
            ws.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    failed = any(c["ok"] is False for c in checks)
    verified = not failed and engine_mode == "live" and all(c["ok"] is True for c in checks)
    return {
        "ok": not failed,
        "verdict": "FAILED" if failed else ("VERIFIED" if verified else "PARTIAL"),
        "engine_mode": engine_mode,
        "checks": checks,
        "wall_s": round(time.monotonic() - t0, 1),
    }


def _failure_diagnostics(ws: Any, run_id: str, missing: list[dict[str, Any]], tail: int = 40) -> dict[str, Any]:
    """Why an engine run failed: each unsuccessful processor with the end of its engine logs."""
    procs = []
    for r in ws.db.conn.execute(
        "SELECT id, processor_id, status, outcome, failure_family FROM processor_run WHERE analysis_run_id=?",
        (run_id,),
    ):
        if str(r["outcome"]).startswith("SUCCESS"):
            continue
        logs = {}
        for name in ("stderr.log", "stdout.log"):
            f = ws.path / "logs" / "processor_runs" / r["id"] / name
            if f.is_file():
                logs[name] = f.read_text(encoding="utf-8", errors="replace").splitlines()[-tail:]
        procs.append({k: r[k] for k in ("processor_id", "status", "outcome", "failure_family")} | {"logs": logs})
    return {"missing_evidence": missing, "processors": procs}


def _golden_extraction_check(ws: Any, demo: Path) -> dict[str, Any]:
    """Live Ghidra output must equal the recorded golden export (D1 fields)."""
    compared, mismatched = 0, []
    for rel, sha in ws.db.conn.execute(
        "SELECT dr.output_relpath, di.input_ref FROM derived_result dr JOIN derived_input di"
        " ON di.derived_result_id = dr.id WHERE dr.processor_id = 'ghidra.extract' AND dr.state = 'CURRENT'"
    ):
        golden_path = demo / "golden" / "ghidra" / f"{sha}.json"
        if not golden_path.is_file():
            continue
        live = json.loads((ws.path / rel / "result.json").read_text(encoding="utf-8"))
        golden = json.loads(golden_path.read_text(encoding="utf-8"))
        compared += 1
        if [(f["entry"], f["insns"]) for f in live["functions"]] != [
            (f["entry"], f["insns"]) for f in golden["functions"]
        ]:
            mismatched.append(sha[:12])
    return {
        "name": "golden Ghidra extraction",
        "ok": compared > 0 and not mismatched,
        "detail": f"{compared} artifact(s) compared" + (f"; mismatch: {mismatched}" if mismatched else ""),
    }
