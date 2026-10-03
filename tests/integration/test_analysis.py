"""Analysis pipeline: DAG, cache, STALE, partial runs, cancel/resume, consensus, lineage (spec V–VII)."""

from __future__ import annotations

import dataclasses
import json
import socket
import threading
from pathlib import Path

import pytest

from acet.analysis import orchestrator as orch
from acet.analysis import registry
from acet.analysis.orchestrator import analyze_build, compare_builds, mark_stale, resume
from acet.domain.error_codes import AcetError
from acet.engines.environment import detect
from acet.ingest.importer import ImportRequest, import_build
from acet.jobs import store as jobs
from acet.lineage.builder import build_lineage

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "datasets" / "demo"
GT = json.loads((DEMO / "ground_truth.json").read_text(encoding="utf-8"))


@pytest.fixture
def replay(monkeypatch):
    """Golden replay of recorded real Ghidra exports (no live engine needed in CI)."""
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DEMO / "golden" / "ghidra"))
    monkeypatch.delenv("ACET_GHIDRA_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("ACET_BINDIFF", raising=False)
    monkeypatch.delenv("ACET_QBINDIFF_PYTHON", raising=False)


def _builds(ws, product_id, versions=(1, 2)):
    return [
        import_build(
            ws,
            ImportRequest([DEMO / "builds" / f"v{v}"], product_id, release_label=str(v), observed_at=f"2026-0{v}-01"),
        ).build_id
        for v in versions
    ]


def test_fast_analysis_real_pe_facts(ws, product_id):
    (b1,) = _builds(ws, product_id, (1,))
    s = analyze_build(ws, b1, "FAST@1")
    assert s.status == "COMPLETED" and s.coverage == 1.0
    row = ws.db.conn.execute(
        "SELECT dr.output_relpath FROM derived_result dr JOIN derived_input di ON di.derived_result_id=dr.id"
        " WHERE dr.processor_id='acet.pe' AND di.input_ref LIKE '52c429bb%'"
    ).fetchone()
    facts = json.loads((ws.path / row[0] / "result.json").read_text(encoding="utf-8"))
    exports = {e["name"] for e in facts["exports"]["value"]["symbols"]}
    assert {"GuardInit", "GuardScan", "GuardTick"} <= exports
    assert facts["headers"]["value"]["magic"] == "PE32+"
    assert facts["authenticode"]["value"] == {"present": False}
    # /brepro stores a content hash in the timestamp field: a fact, never a build date (ACET-PE-002)
    assert isinstance(facts["headers"]["value"]["pe_timestamp"], int)


@pytest.mark.acceptance("ACC-012", "ACC-014", "ACC-107")
def test_cache_hit_and_reproducibility(ws, product_id):
    (b1,) = _builds(ws, product_id, (1,))
    first = analyze_build(ws, b1, "FAST@1")
    second = analyze_build(ws, b1, "FAST@1")
    assert second.cache_hits == len([n for n in second.nodes.values() if n == "SUCCESS"]) == 6
    run = ws.db.conn.execute("SELECT * FROM analysis_run WHERE id=?", (first.run_id,)).fetchone()
    assert run["resolved_config_hash"] and run["engine_pack_id"] and json.loads(run["input_hashes_json"])
    assert run["acet_version"] and run["profile_id"]
    for pr in ws.db.conn.execute("SELECT * FROM processor_run WHERE analysis_run_id=?", (first.run_id,)):
        assert pr["processor_version"] and pr["input_hash"] and pr["config_hash"] and pr["cache_key"]
        assert pr["determinism_class"] in ("D0", "D1", "D2", "D3")
    # ACC-107: no engine work under a long DB transaction
    assert max(ws.db.tx_durations_ms) < 1000


@pytest.mark.acceptance("ACC-013", "ACC-144")
def test_processor_version_change_marks_descendants_stale(ws, product_id, replay, monkeypatch):
    b1, b2 = _builds(ws, product_id)
    compare_builds(ws, b1, b2, "STANDARD@1")
    before = ws.db.conn.execute("SELECT count(*) FROM derived_result").fetchone()[0]
    snapshot = [tuple(r) for r in ws.db.conn.execute("SELECT * FROM consensus_match ORDER BY id")]
    monkeypatch.setitem(
        registry.PROCESSORS, "ghidra.extract", dataclasses.replace(registry.PROCESSORS["ghidra.extract"], version="2")
    )
    changed = mark_stale(ws.db)
    states = dict(
        ws.db.conn.execute("SELECT processor_id, group_concat(DISTINCT state) FROM derived_result GROUP BY 1")
    )
    assert states["ghidra.extract"] == "STALE"
    assert states["acet.features"] == "STALE" and states["acet.consensus"] == "STALE"
    assert states["acet.pe"] == "CURRENT"  # not a descendant: untouched (ACET-ANA-003)
    assert changed >= 4
    assert ws.db.conn.execute("SELECT count(*) FROM derived_result").fetchone()[0] == before  # nothing deleted
    assert [tuple(r) for r in ws.db.conn.execute("SELECT * FROM consensus_match ORDER BY id")] == snapshot


@pytest.mark.acceptance("ACC-011", "ACC-039", "ACC-080")
def test_missing_optional_engine_gives_partial_with_missing_evidence(ws, product_id, replay):
    b1, b2 = _builds(ws, product_id)
    s = compare_builds(ws, b1, b2, "STANDARD@1")
    assert s.status == "COMPLETED_PARTIAL"
    assert 0 < s.coverage < 1
    missing = {m["processor"] for m in s.missing_evidence}
    assert missing == {"ghidriff.diff@1"}
    assert all(m["reason"] for m in s.missing_evidence)
    run = ws.db.conn.execute(
        "SELECT missing_evidence_json, coverage_json FROM analysis_run WHERE id=?", (s.run_id,)
    ).fetchone()
    assert "ghidriff" in run["missing_evidence_json"] and run["coverage_json"]


def test_standard_requires_ghidra(ws, product_id, monkeypatch):
    monkeypatch.delenv("ACET_GHIDRA_REPLAY_DIR", raising=False)
    monkeypatch.delenv("ACET_GHIDRA_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    b1, b2 = _builds(ws, product_id)
    with pytest.raises(AcetError) as ei:
        compare_builds(ws, b1, b2, "STANDARD@1")
    assert ei.value.code == "ACET-GHD-001"


@pytest.mark.acceptance("ACC-015", "ACC-048", "ACC-049", "ACC-131")
def test_consensus_explainable_and_raw_preserved(ws, product_id, replay):
    b1, b2 = _builds(ws, product_id)
    s = compare_builds(ws, b1, b2, "STANDARD@1")
    v1 = GT["functions"]["guardcore.dll"]["v1"]
    v2 = GT["functions"]["guardcore.dll"]["v2"]
    rows = ws.db.conn.execute("SELECT * FROM consensus_match WHERE analysis_run_id=?", (s.run_id,)).fetchall()
    by_left = {json.loads(r["evidence_json"])["left_address"]: r for r in rows if r["left_function_id"]}
    rename = by_left[v1["xor_obfuscate"]]
    ev = json.loads(rename["evidence_json"])
    assert ev["right_address"] == v2["obfuscate_buffer"] and rename["decision"] == "EXACT"
    assert ev["supporting_evidence"] and "contradicting_evidence" in ev and ev["missing_evidence"]
    assert rename["engine_count"] == 1 and rename["evidence_diversity"] >= 3  # diversity ≠ engine count
    assert by_left[v1["report_event"]]["right_function_id"] is None  # unmatched ≠ new
    raw = ws.db.conn.execute(
        "SELECT count(*), sum(raw_score IS NOT NULL) FROM matcher_result WHERE analysis_run_id=?", (s.run_id,)
    ).fetchone()
    assert raw[0] > 0 and raw[0] == raw[1]
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        ws.db.conn.execute("UPDATE matcher_result SET decision='EXACT'")
    with pytest.raises(sqlite3.IntegrityError):
        ws.db.conn.execute("UPDATE consensus_match SET decision='EXACT'")


@pytest.mark.acceptance("ACC-018", "ACC-019")
def test_lineage_split_merge_and_incremental_extension(ws, product_id, replay):
    b1, b2, b3 = _builds(ws, product_id, (1, 2, 3))
    compare_builds(ws, b1, b2, "STANDARD@1")
    first = build_lineage(ws, product_id, [b1, b2])
    links = {
        r["relation"]
        for r in ws.db.conn.execute("SELECT relation FROM lineage_link WHERE analysis_run_id=?", (first.run_id,))
    }
    assert {"SPLIT_PARENT", "MERGE_PARENT"} <= links
    old_rows = [
        tuple(r)
        for r in ws.db.conn.execute("SELECT * FROM lineage_assignment WHERE analysis_run_id=?", (first.run_id,))
    ]
    compare_builds(ws, b2, b3, "STANDARD@1")
    second = build_lineage(ws, product_id, [b1, b2, b3])
    assert second.carried_forward == len(old_rows)
    assert [
        tuple(r)
        for r in ws.db.conn.execute("SELECT * FROM lineage_assignment WHERE analysis_run_id=?", (first.run_id,))
    ] == old_rows
    assert second.relations.get("CONTINUATION", 0) > first.relations.get("CONTINUATION", 0)


@pytest.mark.acceptance("ACC-010")
def test_resume_after_crash_does_not_redo_completed_nodes(ws, product_id):
    (b1,) = _builds(ws, product_id, (1,))

    class Crash(BaseException):
        pass

    count = {"n": 0}

    def fault(stage: str) -> None:
        if stage.startswith("node:"):
            count["n"] += 1
            if count["n"] == 4:
                raise Crash()

    with pytest.raises(Crash):
        analyze_build(ws, b1, "FAST@1", fault=fault)
    job = ws.db.conn.execute("SELECT id FROM job ORDER BY seq DESC LIMIT 1").fetchone()["id"]
    import subprocess
    import sys

    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    ws.db.conn.execute("UPDATE job SET owner_pid=?, owner_host=? WHERE id=?", (p.pid, socket.gethostname(), job))
    assert jobs.recover_interrupted(ws.db) == [job]
    s = resume(ws, job)
    assert s.status == "COMPLETED"
    n = ws.db.conn.execute("SELECT count(*) FROM processor_run WHERE analysis_run_id=?", (s.run_id,)).fetchone()[0]
    assert n == 6  # 3 done before the crash + 3 after; none recorded twice


def test_cancel_keeps_completed_results(ws, product_id):
    (b1,) = _builds(ws, product_id, (1,))
    seen = {"n": 0}

    def fault(stage: str) -> None:
        if stage.startswith("node:"):
            seen["n"] += 1
            if seen["n"] == 3:
                job = ws.db.conn.execute("SELECT id FROM job ORDER BY seq DESC LIMIT 1").fetchone()["id"]
                jobs.transition(ws.db, job, "CANCELLING")

    s = analyze_build(ws, b1, "FAST@1", fault=fault)
    assert s.status == "CANCELLED"
    kept = ws.db.conn.execute("SELECT count(*) FROM derived_result WHERE state='CURRENT'").fetchone()[0]
    assert kept == 3  # ACET-JOB-002: finished results stay cached


@pytest.mark.acceptance("ACC-135", "ACC-136", "ACC-038")
def test_determinism_declared_and_repeat_checked(ws, product_id, monkeypatch):
    assert all(p.determinism.value in ("D0", "D1", "D2", "D3") for p in registry.PROCESSORS.values())
    prof = registry.Profile("FASTREPEAT", 1, ("acet.hash", "acet.pe"), {"determinism_repeats": 2})
    monkeypatch.setitem(registry.PROFILES, prof.ref, prof)
    (b1,) = _builds(ws, product_id, (1,))
    analyze_build(ws, b1, "FASTREPEAT@1")
    for m in ws.db.conn.execute("SELECT metrics_json FROM processor_run WHERE status='COMPLETED'"):
        det = json.loads(m[0])["determinism"]
        assert det["match"] and det["bit_identical"]


@pytest.mark.acceptance("ACC-033")
def test_capabilities_drive_availability(monkeypatch, replay):
    env = detect()
    from acet.domain.enums import Capability

    assert Capability.FUNCTION_EXTRACTION in env.capabilities
    assert env.providers["ghidra"].verified is False  # replay is never a verified live engine
    assert not env.available("ghidriff")
    assert orch.PROCESSORS["ghidra.extract"].capabilities


def test_integrity_gate_blocks_analysis(ws, product_id):
    import os
    import stat

    (b1,) = _builds(ws, product_id, (1,))
    shas = [r[0] for r in ws.db.conn.execute("SELECT sha256 FROM artifact")]
    victim = ws.store.path_for(shas[0])
    os.chmod(victim, stat.S_IREAD | stat.S_IWRITE)
    victim.write_bytes(b"corrupt")
    with pytest.raises(AcetError) as ei:
        analyze_build(ws, b1, "FAST@1")
    assert ei.value.code == "ACET-STO-002"
    assert ws.db.conn.execute("SELECT count(*) FROM analysis_run").fetchone()[0] == 0


def test_concurrent_identical_analyses_share_cache(ws, product_id):
    from acet.application.workspace import open_workspace

    (b1,) = _builds(ws, product_id, (1,))
    results = []

    def run() -> None:
        w = open_workspace(ws.path)
        try:
            results.append(analyze_build(w, b1, "FAST@1"))
        finally:
            w.close()

    ts = [threading.Thread(target=run) for _ in range(3)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(results) == 3
    n = ws.db.conn.execute("SELECT count(*) FROM derived_result").fetchone()[0]
    assert n == 6  # one computation per cache key across concurrent runs (ACET-CON-001)


def test_worker_command_in_a_frozen_build(monkeypatch, tmp_path):
    """PyInstaller: sys.executable is acet.exe / acet-ui.exe, which has no ``-m``."""
    import sys

    from acet.engines.worker import WORKER_ARG, worker_command

    req = tmp_path / "request.json"
    assert worker_command(req)[1:3] == ["-m", "acet.engines.worker"]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "ACET" / "acet-ui.exe"))
    cmd = worker_command(req)
    assert Path(cmd[0]).parent == tmp_path / "ACET" and Path(cmd[0]).stem == "acet"
    assert cmd[1:] == [WORKER_ARG, str(req)]


def test_analysis_through_the_frozen_worker_entry_point(ws, product_id, monkeypatch):
    """Runs every FAST worker through `acet __worker__` (the entry used by the installed app)."""
    import sys

    from acet.engines.worker import WORKER_ARG

    calls: list[str] = []

    def frozen_like(req: Path) -> list[str]:
        calls.append(str(req))
        return [sys.executable, "-m", "acet", WORKER_ARG, str(req)]

    monkeypatch.setattr(orch, "worker_command", frozen_like)
    (b1,) = _builds(ws, product_id, (1,))
    s = analyze_build(ws, b1, "FAST@1")
    assert s.status == "COMPLETED" and s.coverage == 1.0
    assert len(calls) >= 4


def test_ghidriff_runs_in_the_engine_pack_interpreter(monkeypatch, tmp_path):
    import sys

    from acet.engines import environment

    venv = tmp_path / "ghidriff-venv"
    site = venv / "Lib" / "site-packages"
    for dist in ("ghidriff-1.0.0", "pyghidra-2.2.1"):
        (site / f"{dist}.dist-info").mkdir(parents=True)
    py = venv / "Scripts" / "python.exe"
    py.parent.mkdir(parents=True)
    py.write_bytes(b"")
    monkeypatch.setattr(environment, "ghidra_dir", lambda o: None)
    monkeypatch.setenv("ACET_GHIDRIFF_PYTHON", str(py))
    info = environment.detect().providers["ghidriff"]
    assert info.version == "1.0.0" and info.location == str(py)
    assert not info.available  # still needs a live Ghidra
    # A frozen build without an Engine Pack interpreter never claims ghidriff.
    monkeypatch.delenv("ACET_GHIDRIFF_PYTHON")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    info = environment.detect().providers["ghidriff"]
    assert info.version is None and info.location is None and not info.available
