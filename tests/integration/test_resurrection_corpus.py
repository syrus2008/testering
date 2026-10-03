"""Resurrection corpus (datasets/resurrection): real clang/lld-link binaries, recorded real Ghidra
exports (golden replay). v1 → v2 (function A gone) → v3 variant (ACET-LIN-002, resurrect@2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acet.benchmark import scenarios

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets" / "resurrection"
GT = json.loads((DATA / "ground_truth.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def replay(monkeypatch):
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DATA / "golden" / "ghidra"))
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON"):
        monkeypatch.delenv(k, raising=False)


def run_scenario(ws: Any, scenario: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    out = scenarios.run_scenario(ws, DATA, scenario)
    builds, metrics, lin_run = out["builds"], out["lineage"], out["lineage_run"]
    spec = GT["scenarios"][scenario]
    by_name: dict[str, dict[str, Any]] = {}
    v3 = spec["versions"][2]
    for name in ("audit_record", "trace_record"):
        addr = GT["functions"][v3].get(name)
        if addr is None:
            continue
        r = ws.db.conn.execute(
            "SELECT la.lineage_id, la.relation, la.evidence_json FROM lineage_assignment la JOIN function_instance fi"
            " ON fi.id=la.function_instance_id WHERE la.analysis_run_id=? AND la.build_id=? AND fi.address=?"
            " AND la.relation!='DISAPPEARED'",
            (lin_run, builds[2], addr),
        ).fetchone()
        by_name[name] = {
            "lineage": r["lineage_id"],
            "relation": r["relation"],
            "evidence": json.loads(r["evidence_json"]),
        }
    v1_addr = GT["functions"]["v1"]["audit_record"]
    by_name["audit_record@v1"] = {
        "lineage": ws.db.conn.execute(
            "SELECT la.lineage_id FROM lineage_assignment la JOIN function_instance fi ON fi.id=la.function_instance_id"
            " WHERE la.analysis_run_id=? AND la.build_id=? AND fi.address=?",
            (lin_run, builds[0], v1_addr),
        ).fetchone()[0]
    }
    return metrics, by_name


@pytest.mark.acceptance("ACC-019")
def test_identical_return_reuses_the_historical_lineage(ws):
    m, f = run_scenario(ws, "identical")
    assert f["audit_record"]["relation"] == "RESURRECTED_CONFIRMED"
    assert f["audit_record"]["lineage"] == f["audit_record@v1"]["lineage"]
    ev = f["audit_record"]["evidence"]
    assert ev["code"] == "exact" and {"context", "data"} <= set(ev["supporting_families"])
    assert m["purity"] == 1.0 and m["wrong_merge"] == 0 and m["wrong_split"] == 0
    assert m["multi_version_recovery"] == 1.0 and m["resurrections"]["confirmed"] == 1


def test_recompiled_return_is_confirmed_only_on_converging_evidence(ws):
    m, f = run_scenario(ws, "recompiled")
    ev = f["audit_record"]["evidence"]
    assert f["audit_record"]["relation"] == "RESURRECTED_CONFIRMED" and ev["code"] == "similar"
    assert {"context", "data"} <= set(ev["supporting_families"])  # code alone would not do
    assert f["audit_record"]["lineage"] == f["audit_record@v1"]["lineage"]
    assert m["purity"] == 1.0 and m["wrong_split"] == 0 and m["resurrections"]["confirmed"] == 1


def test_heavily_recompiled_return_stays_a_linked_hypothesis(ws):
    m, f = run_scenario(ws, "recompiled_heavy")
    ev = f["audit_record"]["evidence"]
    assert f["audit_record"]["relation"] == "RESURRECTED_CANDIDATE" and ev["code"] is None
    assert f["audit_record"]["lineage"] != f["audit_record@v1"]["lineage"]  # nothing merged
    assert m["purity"] == 1.0 and m["wrong_split_unlinked"] == 0 and m["resurrections"]["candidate_linked"] == 1


def test_lookalike_never_takes_over_the_old_lineage(ws):
    m, f = run_scenario(ws, "lookalike")
    trace = f["trace_record"]
    assert trace["relation"] == "UNRESOLVED" and trace["lineage"] != f["audit_record@v1"]["lineage"]
    rejected = trace["evidence"]["rejected_resurrection"]
    assert rejected["status"] == "REJECTED" and "data" in rejected["contradicting_families"]
    assert m["purity"] == 1.0 and m["wrong_merge"] == 0
    links = ws.db.conn.execute("SELECT count(*) FROM lineage_link WHERE relation LIKE 'RESURRECTED%'").fetchone()[0]
    assert links == 0  # not even a hypothesis
    assert m["false_resurrection_candidates"] == 0
