"""Live engine integration (runs only where an Engine Pack is installed: ACET_GHIDRA_DIR etc.)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from acet.analysis.orchestrator import compare_builds
from acet.ingest.importer import ImportRequest, import_build

DEMO = Path(__file__).resolve().parents[2] / "datasets" / "demo"
pytestmark = pytest.mark.skipif(not os.environ.get("ACET_GHIDRA_DIR"), reason="no live Ghidra (Engine Pack)")


@pytest.mark.acceptance("ACC-038")
def test_live_standard_matches_golden_extraction(ws, product_id):
    b1 = import_build(ws, ImportRequest([DEMO / "builds" / "v1"], product_id)).build_id
    b2 = import_build(ws, ImportRequest([DEMO / "builds" / "v2"], product_id)).build_id
    s = compare_builds(ws, b1, b2, "STANDARD@1")
    assert s.status in ("COMPLETED", "COMPLETED_PARTIAL")
    for rel, sha in ws.db.conn.execute(
        "SELECT dr.output_relpath, di.input_ref FROM derived_result dr JOIN derived_input di ON"
        " di.derived_result_id=dr.id WHERE dr.processor_id='ghidra.extract'"
    ):
        live = json.loads((ws.path / rel / "result.json").read_text())
        golden = json.loads((DEMO / "golden" / "ghidra" / f"{sha}.json").read_text())
        # D1 golden: same functions, same normalized instructions (engine metadata may differ)
        assert [(f["entry"], f["insns"]) for f in live["functions"]] == [
            (f["entry"], f["insns"]) for f in golden["functions"]
        ]


def _doctor_full(extra_env: dict[str, str]) -> tuple[int, dict]:
    """The real command, in a fresh process, as an operator would run it."""
    env = {k: v for k, v in os.environ.items() if k != "ACET_WORKSPACE"}
    env.update(extra_env)
    res = subprocess.run(
        [sys.executable, "-m", "acet", "doctor", "--full", "--json"],
        capture_output=True,
        text=True,
        env=env,
        timeout=1800,
    )
    return res.returncode, json.loads(res.stdout)


@pytest.mark.acceptance("ACC-026")
def test_doctor_full_runs_a_live_golden_self_test():
    code, out = _doctor_full({})
    st = next(c for c in out["checks"] if c["name"] == "golden self-test")
    self_test = st["data"]["self_test"]
    assert self_test["verdict"] == "VERIFIED" and self_test["engine_mode"] == "live", self_test
    assert st["status"] == "OK"
    names = {c["name"]: c["ok"] for c in self_test["checks"]}
    assert names == {
        "import": True,
        "FAST facts": True,
        "STANDARD golden consensus": True,
        "golden Ghidra extraction": True,
    }
    assert code in (0, 10)  # 10 only if an unrelated optional capability is DEGRADED


def test_live_deep_with_all_providers(ws, product_id):
    if not (os.environ.get("ACET_BINDIFF") and os.environ.get("ACET_QBINDIFF_PYTHON")):
        pytest.skip("BinDiff/QBinDiff not installed")
    b1 = import_build(ws, ImportRequest([DEMO / "builds" / "v1"], product_id)).build_id
    b2 = import_build(ws, ImportRequest([DEMO / "builds" / "v2"], product_id)).build_id
    s = compare_builds(ws, b1, b2, "DEEP@1")
    assert s.status == "COMPLETED" and s.coverage == 1.0
    engines = {r[0] for r in ws.db.conn.execute("SELECT DISTINCT engine FROM matcher_result")}
    assert engines == {"acet.featurematch", "ghidriff", "bindiff", "qbindiff"}
