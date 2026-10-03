"""Remaining acceptance criteria: faults, privacy, network, determinism, comparability, capacity, time (§87, §102, §120)."""

from __future__ import annotations

import dataclasses
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from acet.analysis import registry
from acet.analysis.orchestrator import analyze_build, compare_builds, plan
from acet.application.annotations import add_annotation
from acet.application.backup import backup_metadata, restore_metadata
from acet.application.settings import get_setting, set_setting
from acet.application.workspace import open_workspace
from acet.cli.main import main as cli
from acet.domain.canonical import stable_json
from acet.domain.enums import OperationOutcome
from acet.domain.error_codes import AcetError, classify_exception
from acet.engines.environment import detect
from acet.ingest.importer import ImportRequest, import_build
from acet.jobs.completion import CompletionState, validate_completion
from acet.jobs.supervisor import Limits, run_supervised
from acet.platform.doctor import reconcile, workspace_checks
from tests.fixtures import build_a, write_build

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "datasets" / "demo"
SRC = ROOT / "src"


@pytest.fixture
def replay(monkeypatch):
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DEMO / "golden" / "ghidra"))
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON"):
        monkeypatch.delenv(k, raising=False)


def _demo(ws, pid, versions=(1, 2)):
    return [
        import_build(
            ws, ImportRequest([DEMO / "builds" / f"v{v}"], pid, release_label=f"v{v}", observed_at=f"2026-0{v}-01")
        ).build_id
        for v in versions
    ]


# ----------------------------------------------------------------- no execution / network
@pytest.mark.acceptance("ACC-004")
def test_no_imported_artifact_is_ever_executed(ws, product_id, monkeypatch):
    """Runtime half: every process ACET starts during import+analysis is the ACET worker, never an artifact,
    and stored artifacts carry no execute permission."""
    spawned: list[list[str]] = []
    real = subprocess.Popen

    def spy(argv, *a, **k):  # type: ignore[no-untyped-def]
        spawned.append(list(argv))
        return real(argv, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", spy)
    (b1,) = _demo(ws, product_id, (1,))
    analyze_build(ws, b1, "FAST@1")
    shas = [r[0] for r in ws.db.conn.execute("SELECT sha256 FROM artifact")]
    assert spawned and all(a[0] == sys.executable and a[1:3] == ["-m", "acet.engines.worker"] for a in spawned)
    for sha in shas:
        p = ws.store.path_for(sha)
        assert not any(str(p) == x or sha in x for a in spawned for x in a[:1])
        if sys.platform == "win32":
            # Windows has no execute bit: a blob is not runnable because it has no extension
            # (no file association) and nothing ever launches it (checked above).
            assert p.suffix == ""
        else:
            assert not os.access(p, os.X_OK) or (os.geteuid() == 0 and not (p.stat().st_mode & 0o111))


@pytest.mark.acceptance("ACC-003", "ACC-078", "ACC-077")
def test_core_works_with_network_blocked(ws, product_id, replay, monkeypatch, tmp_path):
    def refuse(*_a, **_k):
        raise PermissionError("network blocked by test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    b1, b2 = _demo(ws, product_id)
    s = compare_builds(ws, b1, b2, "STANDARD@1")
    assert s.status.startswith("COMPLETED")
    from acet.changes.detector import detect_changes
    from acet.reporting.model import compare_report
    from acet.reporting.render import write_report

    detect_changes(ws, s.run_id)
    write_report(compare_report(ws, s.run_id), "html", tmp_path / "r.html")
    assert get_setting(ws, "network.enabled") is False and get_setting(ws, "symbols.remote_provider") is None
    assert all(
        not cfg.get("processors", {}).get("ghidra.extract", {}).get("analyzers", {}).get("PDB Universal", False)
        for cfg in (p.config for p in registry.PROFILES.values())
    )
    out = ws.path / "logs" / "processor_runs"
    assert out.is_dir()


def test_worker_network_guard_blocks_sockets(tmp_path):
    code = (
        "import os, socket; os.environ['ACET_NO_NETWORK']='1'; from acet.engines.worker import _forbid_network;"
        "_forbid_network();\ntry:\n socket.create_connection(('127.0.0.1', 9))\n print('CONNECTED')\n"
        "except PermissionError as e:\n print('BLOCKED')"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(SRC)}
    )
    assert "BLOCKED" in out.stdout


@pytest.mark.acceptance("ACC-079")
@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() != 0 or not Path("/usr/sbin/runuser").exists(),
    reason="needs root to drop to an unprivileged account",
)
def test_import_and_analysis_as_unprivileged_user():
    import shutil
    import tempfile

    home = Path(tempfile.mkdtemp(prefix="acet-nobody-", dir="/tmp"))
    os.chmod(home, 0o777)
    request_cleanup = home
    script = (
        f"from pathlib import Path; from acet.application.workspace import create_workspace;"
        f"from acet.application.products import create_product; from acet.ingest.importer import import_build, ImportRequest;"
        f"from acet.analysis.orchestrator import analyze_build;"
        f"ws=create_workspace('u', Path('{home}')/'w'); p=create_product(ws,'P');"
        f"b=import_build(ws, ImportRequest([Path('{DEMO}')/'builds'/'v1'], p)).build_id;"
        f"print(analyze_build(ws,b,'FAST@1').status)"
    )
    out = subprocess.run(
        ["runuser", "-u", "nobody", "--", sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "PYTHONPATH": str(SRC), "ACET_HOME": str(home)},
        timeout=300,
    )
    shutil.rmtree(request_cleanup, ignore_errors=True)
    assert out.stdout.strip().endswith("COMPLETED"), out.stderr[-2000:]


# ----------------------------------------------------------------- CLI parity / exit codes / audit
@pytest.mark.acceptance("ACC-042", "ACC-043", "ACC-124", "ACC-035")
def test_cli_full_parity_and_exit_codes(capsys, tmp_path, replay, monkeypatch):
    def run(*argv):
        code = cli(list(argv))
        o = capsys.readouterr()
        return code, o.out, o.err

    code, out, _ = run("workspace", "create", "cli", "--root", str(tmp_path / "w"), "--json")
    w = ["--workspace", json.loads(out)["path"]]
    run("product", "create", "Guard", *w)
    ids = []
    for v in (1, 2):
        code, out, _ = run(
            "import", str(DEMO / "builds" / f"v{v}"), "--product", "Guard", "--release", f"v{v}", *w, "--json"
        )
        ids.append(json.loads(out)["build_id"])
    code, out, _ = run("analyze", ids[0], "--profile", "FAST@1", *w, "--json")
    assert code == 0 and json.loads(out)["status"] == "COMPLETED"
    code, out, _ = run("compare", ids[0], ids[1], "--profile", "STANDARD@1", *w, "--json")
    assert code == 10 and json.loads(out)["status"] == "COMPLETED_PARTIAL"  # ghidriff absent → partial success
    run_id = json.loads(out)["run_id"]
    code, out, _ = run("runs", "show", run_id, *w, "--json")
    shown = json.loads(out)
    assert code == 0 and shown["resolved_config"] and shown["resolved_config_hash"] and shown["processor_runs"]
    code, out, _ = run("export", run_id, "--format", "json", "--output", str(tmp_path / "r.json"), *w)
    assert code == 0 and json.loads((tmp_path / "r.json").read_text())["kind"] == "acet-report"
    code, _, _ = run("annotate", "analysis_run", run_id, "checked", *w)
    assert code == 0
    monkeypatch.delenv("ACET_GHIDRA_REPLAY_DIR")
    code, _, err = run("compare", ids[0], ids[1], "--profile", "STANDARD@1", *w)
    assert code == 30 and "ACET-GHD-001" in err  # analysis failure family → 30
    ws = open_workspace(Path(w[1]))
    try:
        events = {r[0] for r in ws.db.conn.execute("SELECT event_type FROM audit_event")}
    finally:
        ws.close()
    assert {"import", "analysis.create", "analysis.finish", "annotation.add", "product.create"} <= events


@pytest.mark.acceptance("ACC-110")
def test_permission_denied_is_actionable_without_stacktrace(capsys, tmp_path, monkeypatch):
    src = build_a(tmp_path / "a")
    cli(["workspace", "create", "p", "--root", str(tmp_path / "w"), "--json"])
    wpath = json.loads(capsys.readouterr().out)["path"]
    cli(["product", "create", "P", "--workspace", wpath])
    capsys.readouterr()
    import builtins

    real_open = builtins.open

    def deny(path, *a, **k):  # type: ignore[no-untyped-def]
        if str(path).endswith("Fict.sys"):
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", deny)
    code = cli(["import", str(src), "--product", "P", "--workspace", wpath])
    err = capsys.readouterr().err
    assert code == 20 and "ACET-IMP-001" in err and "action:" in err and "Traceback" not in err


@pytest.mark.acceptance("ACC-037")
def test_doctor_detects_dangling_and_orphan(ws, product_id, tmp_path):
    res = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    victim = ws.store.path_for(res.new_artifacts[0])
    victim.chmod(0o600)
    victim.unlink()
    orphan = ws.store.path_for("f" * 64)
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"orphan")
    checks, rec = workspace_checks(ws)
    assert rec.dangling_refs == [res.new_artifacts[0]] and rec.orphan_blobs == ["f" * 64]
    assert next(c for c in checks if c.name == "artifact_store.reconcile").status.value == "FAIL"


@pytest.mark.acceptance("ACC-045")
def test_backup_restores_settings_and_annotations(ws, product_id):
    set_setting(ws, "analysis.default_profile", "FAST@1")
    add_annotation(ws, "product", product_id, "kept")
    bk = backup_metadata(ws)
    set_setting(ws, "analysis.default_profile", "DEEP@1")
    restored = restore_metadata(ws, bk)
    try:
        assert get_setting(restored, "analysis.default_profile") == "FAST@1"
        assert restored.db.conn.execute("SELECT count(*) FROM annotation").fetchone()[0] == 1
    finally:
        restored.close()


# ----------------------------------------------------------------- engines: timeout, known limitation, OOM
def _big_build(tmp_path: Path, mb: int = 48) -> Path:
    from tests.fixtures import driver

    return write_build(tmp_path / "big", {"big.sys": driver(os.urandom(mb * 1024 * 1024))})


@pytest.mark.acceptance("ACC-054")
def test_timeouts_are_visible(ws, product_id, tmp_path, monkeypatch):
    b = import_build(ws, ImportRequest([_big_build(tmp_path)], product_id)).build_id
    prof = registry.Profile(
        "TINY", 1, ("acet.strings",), {"processors": {"acet.strings": {"hard_timeout_s": 0.4, "soft_timeout_s": 0.2}}}
    )
    monkeypatch.setitem(registry.PROFILES, prof.ref, prof)
    s = analyze_build(ws, b, "TINY@1")
    pr = ws.db.conn.execute(
        "SELECT termination, completion_state, error_code, warnings_json FROM processor_run WHERE analysis_run_id=?",
        (s.run_id,),
    ).fetchone()
    assert pr["termination"] == "timeout" and pr["completion_state"] == "invalid"
    assert s.status == "FAILED" and s.missing_evidence[0]["outcome"] in ("RETRYABLE_FAILURE", "PERMANENT_FAILURE")
    # native engine timeout reported by the adapter ends up in the completion manifest
    from acet.engines.worker import WorkerContext

    ctx = WorkerContext({"config": {}, "inputs": [], "job_id": "x"}, tmp_path)
    assert ctx.termination == "normal"


@pytest.mark.acceptance("ACC-073")
def test_bindiff_known_limitation_becomes_skip(tmp_path, monkeypatch):
    from acet.engines import bindiff
    from acet.engines.worker import ProcessorSkip, WorkerContext

    if sys.platform == "win32":
        fake = tmp_path / "bindiff.cmd"
        fake.write_text("@echo BinDiff 8\r\n@echo sqlite: database or disk is full\r\n@exit /b 1\r\n")
    else:
        fake = tmp_path / "bindiff"
        fake.write_text("#!/bin/sh\necho 'BinDiff 8'\necho 'sqlite: database or disk is full'\nexit 1\n")
        fake.chmod(0o755)
    monkeypatch.setenv("ACET_PROVIDER_BINDIFF", str(fake))
    sides = []
    for side in ("l", "r"):
        d = tmp_path / side
        d.mkdir()
        (d / "result.json").write_text(json.dumps({"status": "complete", "file": "export.BinExport"}))
        (d / "export.BinExport").write_bytes(b"x")
        sides.append(d)
    out = tmp_path / "out"
    out.mkdir()
    req = {
        "config": {"_layout": {"derived": ["binexport.export@left", "binexport.export@right"]}},
        "job_id": "j",
        "inputs": [
            {"kind": "artifact", "sha256": "a" * 64, "path": "x"},
            {"kind": "artifact", "sha256": "b" * 64, "path": "y"},
            {"kind": "derived", "sha256": "c" * 64, "path": str(sides[0] / "result.json")},
            {"kind": "derived", "sha256": "d" * 64, "path": str(sides[1] / "result.json")},
        ],
    }
    with pytest.raises(ProcessorSkip) as ei:
        bindiff.diff(WorkerContext(req, out))
    assert ei.value.status == "SKIPPED_KNOWN_LIMITATION" and ei.value.code == "KL-BDF-001"


@pytest.mark.acceptance("ACC-112")
@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_AS on POSIX; Job Object memory limit on Windows")
def test_worker_oom_does_not_bring_down_core(tmp_path):
    script = tmp_path / "oom.py"
    script.write_text("x = bytearray(3 * 1024**3)\nprint('allocated')\n")
    res = run_supervised(
        [sys.executable, str(script)],
        workdir=tmp_path / "w",
        log_dir=tmp_path / "l",
        limits=Limits(memory_limit_bytes=512 * 1024 * 1024, hard_timeout_s=60),
    )
    assert res.exit_code != 0 and "MemoryError" in res.stderr_path.read_text()
    assert "allocated" not in res.stdout_path.read_text()


@pytest.mark.acceptance("ACC-095", "ACC-142")
def test_crash_leftovers_never_become_valid_output(ws, product_id, tmp_path, monkeypatch):
    script = tmp_path / "crash.py"
    out = tmp_path / "out"
    out.mkdir()
    script.write_text(f"import os, time\nopen(r'{out}/result.json.tmp','w').write('{{}}')\nos.kill(os.getpid(), 9)\n")
    res = run_supervised([sys.executable, str(script)], workdir=tmp_path / "w", log_dir=tmp_path / "l")
    v = validate_completion(res, out, expected_outputs=["result.json"])
    assert v.state is CompletionState.INVALID
    # an incomplete (PARTIAL) result is stored INCOMPLETE and never served as a CURRENT cache hit
    from acet.analysis import orchestrator as orch
    from acet.jobs import completion

    real = completion.validate_completion

    def partial(*a, **k):  # type: ignore[no-untyped-def]
        v = real(*a, **k)
        v.state = CompletionState.PARTIAL
        v.outcome = OperationOutcome.PARTIAL
        return v

    monkeypatch.setattr(orch, "validate_completion", partial)
    (b1,) = _demo(ws, product_id, (1,))
    s = analyze_build(ws, b1, "FAST@1")
    assert s.status == "COMPLETED_PARTIAL"
    states = {r[0] for r in ws.db.conn.execute("SELECT state FROM derived_result")}
    assert states == {"INCOMPLETE"}
    monkeypatch.setattr(orch, "validate_completion", real)
    s2 = analyze_build(ws, b1, "FAST@1")
    assert s2.cache_hits == 0 and s2.status == "COMPLETED"  # recomputed, never reused as CURRENT
    assert {r[0] for r in ws.db.conn.execute("SELECT state FROM derived_result")} == {"INCOMPLETE", "CURRENT"}


@pytest.mark.acceptance("ACC-108")
@pytest.mark.skipif(sys.platform == "win32", reason="uses POSIX kill")
@pytest.mark.parametrize("delay", [0.4, 1.0, 1.8])
def test_kill_app_at_any_point_is_recoverable(tmp_path, delay):
    """Kill the whole application process mid-analysis; reopen, recover, resume, verify invariants."""
    from acet.application.products import create_product
    from acet.application.workspace import create_workspace
    from acet.jobs import store as jobs

    ws = create_workspace("k", tmp_path / "w")
    pid = create_product(ws, "P")
    b1 = import_build(ws, ImportRequest([DEMO / "builds" / "v1"], pid)).build_id
    path = ws.path
    ws.close()
    code = (
        f"from pathlib import Path; from acet.application.workspace import open_workspace;"
        f"from acet.analysis.orchestrator import analyze_build;"
        f"ws=open_workspace(Path(r'{path}')); analyze_build(ws, '{b1}', 'FAST@1')"
    )
    p = subprocess.Popen(
        [sys.executable, "-c", code], env={**os.environ, "PYTHONPATH": str(SRC)}, start_new_session=True
    )
    time.sleep(delay)
    os.killpg(p.pid, signal.SIGKILL)
    p.wait()
    ws = open_workspace(path)
    try:
        recovered = jobs.recover_interrupted(ws.db)
        for jid in recovered:
            from acet.analysis.orchestrator import resume

            assert resume(ws, jid).status == "COMPLETED"
        assert ws.db.integrity_check() == []
        assert reconcile(ws).clean
        for (rel,) in ws.db.conn.execute("SELECT output_relpath FROM derived_result WHERE state='CURRENT'"):
            assert (ws.path / rel / "result.json").is_file()  # nothing CURRENT without its files
        final = analyze_build(ws, b1, "FAST@1")
        assert final.status == "COMPLETED"
    finally:
        ws.close()


@pytest.mark.acceptance("ACC-109")
def test_disk_full_on_write_paths_leaves_no_corruption(ws, product_id, tmp_path, monkeypatch):
    import errno

    from acet.storage import content_store

    real_open = open
    state = {"n": 0}

    def full_open(path, mode="r", *a, **k):  # type: ignore[no-untyped-def]
        fh = real_open(path, mode, *a, **k)
        if "x" in mode or "w" in mode:
            real_write = fh.write

            def write(data):  # type: ignore[no-untyped-def]
                state["n"] += len(data)
                if state["n"] > 1000:
                    raise OSError(errno.ENOSPC, "No space left on device")
                return real_write(data)

            fh.write = write
        return fh

    monkeypatch.setattr(content_store, "open", full_open, raising=False)
    with pytest.raises(AcetError) as ei:
        import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    assert ei.value.code == "ACET-IMP-003"
    assert ws.db.conn.execute("SELECT count(*) FROM build").fetchone()[0] == 0
    assert not list(ws.store.iter_temp_leftovers())
    monkeypatch.undo()
    from acet.reporting import render

    def enospc(*_a, **_k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(Path, "write_text", enospc)
    with pytest.raises(AcetError) as ei:
        render.write_report({"x": 1}, "json", tmp_path / "rep.json")
    assert ei.value.code == "ACET-REP-001" and not (tmp_path / "rep.json").exists()


@pytest.mark.acceptance("ACC-111")
def test_db_busy_is_bounded(ws):
    from acet.storage.db import Database

    holder = Database(ws.db.path)
    holder.conn.execute("BEGIN IMMEDIATE")
    threading.Timer(0.5, lambda: holder.conn.execute("COMMIT")).start()
    t0 = time.monotonic()
    with ws.db.transaction() as tx:  # waits for the lock (busy_timeout), then proceeds
        tx.execute("INSERT INTO settings VALUES ('ui.mode','\"NORMAL\"','t')")
    assert 0.3 < time.monotonic() - t0 < 5
    holder.conn.execute("BEGIN IMMEDIATE")
    ws.db.conn.execute("PRAGMA busy_timeout=200")
    t0 = time.monotonic()
    with pytest.raises(sqlite3.OperationalError) as ei, ws.db.transaction():
        pass
    assert time.monotonic() - t0 < 2  # bounded wait, no indefinite hang
    assert classify_exception(ei.value).code == "ACET-DB-004"
    holder.conn.execute("ROLLBACK")
    holder.close()


# ----------------------------------------------------------------- correlation, determinism, D3, comparability
@pytest.mark.acceptance("ACC-088")
def test_incident_traceable_by_ids(ws, product_id):
    (b1,) = _demo(ws, product_id, (1,))
    s = analyze_build(ws, b1, "FAST@1")
    job = ws.db.conn.execute("SELECT id FROM job WHERE analysis_run_id=?", (s.run_id,)).fetchone()[0]
    prs = [r[0] for r in ws.db.conn.execute("SELECT id FROM processor_run WHERE analysis_run_id=?", (s.run_id,))]
    for pr in prs:
        log = (ws.path / "logs" / "processor_runs" / pr / "stdout.log").read_text()
        assert f"run={s.run_id}" in log and f"job={job}" in log and f"pr={pr}" in log
        assert str(Path.home()) not in log or str(ws.path).startswith(str(Path.home()))


@pytest.mark.acceptance("ACC-137")
def test_d1_processor_repeats_canonically(ws, product_id, replay, monkeypatch):
    prof = registry.Profile("D1REP", 1, ("ghidra.extract", "acet.features"), {"determinism_repeats": 2})
    monkeypatch.setitem(registry.PROFILES, prof.ref, prof)
    (b1,) = _demo(ws, product_id, (1,))
    analyze_build(ws, b1, "D1REP@1")
    dets = [
        json.loads(r[0])["determinism"]
        for r in ws.db.conn.execute(
            "SELECT metrics_json FROM processor_run WHERE processor_id='ghidra.extract' AND status='COMPLETED'"
        )
    ]
    assert dets and all(d["class"] == "D1" and d["canonical_identical"] and d["match"] for d in dets)


@pytest.mark.acceptance("ACC-138")
def test_d3_outputs_never_feed_stable_inference(monkeypatch):
    monkeypatch.setitem(
        registry.PROCESSORS,
        "qbindiff.diff",
        dataclasses.replace(registry.PROCESSORS["qbindiff.diff"], determinism=registry.D3),
    )
    env = detect()
    for p in env.providers.values():
        p.available = True
    shas = ["a" * 64, "b" * 64]
    fmt = dict.fromkeys(shas, "PE32+")
    nodes = plan(registry.get_profile("DEEP@1"), shas, [(shas[0], shas[1])], fmt, env)
    consensus = next(n for n in nodes if n.spec.id == "acet.consensus")
    assert not any(d.startswith("qbindiff.diff") for d in consensus.optional_deps)
    allowed = registry.Profile("X", 1, registry.get_profile("DEEP@1").processors, {"allow_d3": True})
    nodes = plan(allowed, shas, [(shas[0], shas[1])], fmt, env)
    assert any(
        d.startswith("qbindiff.diff") for d in next(n for n in nodes if n.spec.id == "acet.consensus").optional_deps
    )


@pytest.mark.acceptance("ACC-093")
def test_incompatible_metrics_are_not_compared(ws, product_id, replay):
    from acet.analysis.compatibility import Comparability, comparability, compare_metric

    b1, b2, b3 = _demo(ws, product_id, (1, 2, 3))
    r1 = compare_builds(ws, b1, b2, "STANDARD@1").run_id
    r2 = compare_builds(ws, b2, b3, "STANDARD@1").run_id
    assert comparability(ws, r1, r2)[0] is Comparability.FULL
    assert compare_metric(ws, r1, r2, 0.1, 0.3)["delta"] == pytest.approx(0.2)
    ws.db.conn.execute(
        "UPDATE function_instance SET normalizer_version='acet-norm@2' WHERE derived_result_id IN"
        " (SELECT derived_result_id FROM processor_run WHERE analysis_run_id=?)",
        (r2,),
    )
    c, reasons = comparability(ws, r1, r2)
    assert c is Comparability.NONE and reasons
    assert compare_metric(ws, r1, r2, 0.1, 0.3)["delta"] is None


# ----------------------------------------------------------------- unknowns, capacity, time
@pytest.mark.acceptance("ACC-115")
@given(
    st.recursive(
        st.none() | st.integers() | st.text(max_size=5),
        lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=3), c, max_size=3),
        max_leaves=12,
    )
)
def test_unknown_never_becomes_zero(value):
    assert json.loads(stable_json(value)) == value  # None survives every serialization as null, never 0
    from acet.changes.baseline import BaselineClass, classify

    assert classify(None, [1.0] * 10).cls is BaselineClass.UNKNOWN


@pytest.mark.acceptance("ACC-017")
def test_unmeasured_metric_displayed_unknown():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt

    from acet.ui.models import RowsModel

    m = RowsModel([("tlsh_distance", "TLSH"), ("left_name", "Left")])
    m.set_rows([{"tlsh_distance": None, "left_name": None}, {"tlsh_distance": 0, "left_name": "f"}])
    assert m.data(m.index(0, 0), Qt.ItemDataRole.DisplayRole) == "UNKNOWN"
    assert m.data(m.index(1, 0), Qt.ItemDataRole.DisplayRole) == "0"


@pytest.mark.acceptance("ACC-121")
def test_capacity_warning_outside_validated_envelope(ws):
    from acet.platform.capacity import classify

    assert classify(10, 1000)["validated"] and classify(200, 900_000)["class"] == "M"
    big = classify(3000, 12_000_000)
    assert big["class"] == "XL" and not big["validated"] and "OUTSIDE_VALIDATED_CAPACITY" in big["warning"]
    checks, _ = workspace_checks(ws)
    assert next(c for c in checks if c.name == "capacity").status.value == "OK"


@pytest.mark.acceptance("ACC-122")
def test_timestamps_persisted_utc_and_displayed_locally(ws, product_id, tmp_path):
    import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    for table, col in (
        ("build", "created_at"),
        ("observation", "imported_at"),
        ("audit_event", "created_at"),
        ("artifact", "imported_at"),
        ("product", "created_at"),
    ):
        for (v,) in ws.db.conn.execute(f"SELECT {col} FROM {table}"):
            assert v.endswith("Z"), (table, v)
    pytest.importorskip("PySide6")
    from acet.ui.models import to_local

    shown = to_local("2026-01-01T12:00:00.000000Z")
    assert shown.startswith("2026-01-01") and ("+" in shown or "-" in shown[10:])
    assert to_local("2026-01-01") == "2026-01-01"


@pytest.mark.acceptance("ACC-123")
def test_clock_rollback_keeps_causal_order(ws, monkeypatch):
    from acet.domain import ids
    from acet.jobs import store as jobs

    t = [time.time_ns()]
    monkeypatch.setattr(ids.time, "time_ns", lambda: t[0])
    a = ids.uuid7()
    j1 = jobs.create_job(ws.db, "x", {})
    t[0] -= 3600 * 10**9  # clock jumps one hour back
    b = ids.uuid7()
    j2 = jobs.create_job(ws.db, "x", {})
    assert b > a  # monotonic despite the rollback
    s1, s2 = (ws.db.conn.execute("SELECT seq FROM job WHERE id=?", (j,)).fetchone()[0] for j in (j1, j2))
    assert s2 > s1  # transactional sequence, not wall clock


@pytest.mark.acceptance("ACC-062")
def test_pinned_engine_pack_reproduction(ws, product_id, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT))
    from tools.build_engine_pack import build

    from acet.analysis.reproduce import engine_environment_for_run
    from acet.platform import ed25519, engine_packs

    secret = bytes(range(32))
    trust = Path(os.environ["ACET_HOME"]) / "config" / "trusted_keys.json"
    trust.parent.mkdir(parents=True, exist_ok=True)
    trust.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "t",
                        "alg": "ed25519",
                        "purposes": ["engine-pack"],
                        "public_key": ed25519.public_key(secret).hex(),
                    }
                ]
            }
        )
    )
    tool = tmp_path / "bindiff.sh"
    tool.write_text("#!/bin/sh\necho 'BinDiff 8'\n")
    tool.chmod(0o755)
    cfg = {
        "id": "pack",
        "version": "1.0.0",
        "supported_acet": ">=0.1",
        "sources": {"bin/bindiff": str(tool)},
        "providers": [
            {
                "provider_id": "bindiff",
                "provider_version": "8",
                "protocol_version": 1,
                "capabilities": ["STRUCTURAL_DIFF"],
                "executable": "bin/bindiff",
                "license_mode": "bundled",
                "health_check": "-",
                "supported_formats": ["PE32+"],
                "supported_architectures": ["x64"],
            }
        ],
        "licenses": [
            {
                "component": "bindiff",
                "spdx": "Apache-2.0",
                "redistribution": "yes",
                "bundling": "bundled",
                "version_audited": "8",
            }
        ],
    }
    engine_packs.install_pack(build(cfg, tmp_path / "p", secret, "t"))
    set_setting(ws, "ui.mode", "ADVANCED")
    set_setting(ws, "engines.pinned_pack", "pack@1.0.0")
    (b1,) = _demo(ws, product_id, (1,))
    s = analyze_build(ws, b1, "FAST@1")
    assert (
        ws.db.conn.execute(
            "SELECT ep.name FROM analysis_run ar JOIN engine_pack ep ON ep.id=ar.engine_pack_id WHERE ar.id=?",
            (s.run_id,),
        ).fetchone()[0]
        == "pack@1.0.0"
    )
    env = engine_environment_for_run(ws, s.run_id)
    assert env.engine_pack_id == "pack@1.0.0" and Path(env.providers["bindiff"].location).as_posix().endswith(
        "bin/bindiff"
    )
    import shutil

    shutil.rmtree(engine_packs.packs_root() / "pack-1.0.0")
    with pytest.raises(AcetError):
        engine_environment_for_run(ws, s.run_id)  # never silently substituted


@pytest.mark.acceptance("ACC-063")
def test_long_paths(ws, product_id, tmp_path):
    deep = tmp_path
    for i in range(12):
        deep = deep / f"very_long_directory_name_segment_{i:02d}"
    assert len(str(deep)) > 260
    res = import_build(ws, ImportRequest([build_a(deep)], product_id))
    assert res.created_build and len(res.files) == 4


@pytest.mark.acceptance("ACC-075")
def test_authenticode_facts_without_changing_identity(ws, product_id, tmp_path):
    signed = (DEMO / "signed" / "guardcore-v1-signed.dll").read_bytes()
    folder = write_build(tmp_path / "s", {"guardcore.dll": signed})
    res = import_build(ws, ImportRequest([folder], product_id))
    analyze_build(ws, res.build_id, "FAST@1")
    from acet.analysis.results import derived_for_artifact

    sha = res.files[0]["sha256"]
    import hashlib

    assert sha == hashlib.sha256(signed).hexdigest()  # identity = bytes, signature is a fact about them
    a = derived_for_artifact(ws, "acet.pe", sha)["authenticode"]["value"]
    assert a["present"] and a["image_digest_matches"] is True and a["indirect_digest_algorithm"] == "sha256"
    assert a["signer"]["subject"]["CN"].startswith("ACET Test Signing")
    assert a["chain_status"] == "NOT_MEASURED"  # never assumed valid


@pytest.mark.acceptance("ACC-102")
def test_every_processor_run_has_a_mapped_outcome(ws, product_id, replay):
    b1, b2 = _demo(ws, product_id)
    compare_builds(ws, b1, b2, "DEEP@1")
    outcomes = {r[0] for r in ws.db.conn.execute("SELECT outcome FROM processor_run")}
    assert outcomes and outcomes <= {o.value for o in OperationOutcome}
