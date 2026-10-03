"""Golden functional self-test (spec §29, §38; ACC-002/026/100).

Runs in a throw-away workspace on the bundled demo dataset and checks the expected,
deterministic results: FAST facts always; STANDARD consensus when Ghidra (live or golden
replay) is available.
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


def run_self_test(*, standard: bool = True) -> dict[str, Any]:
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
        return {"ok": False, "checks": [{"name": "demo dataset", "ok": False, "detail": "not found"}]}
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
            env = detect()
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
                checks.append(
                    {
                        "name": "STANDARD golden consensus",
                        "ok": ok and c.status.startswith("COMPLETED"),
                        "detail": f"{c.status}; engine={env.providers['ghidra'].version}",
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
    return {
        "ok": all(c["ok"] is not False for c in checks),
        "checks": checks,
        "wall_s": round(time.monotonic() - t0, 1),
    }
