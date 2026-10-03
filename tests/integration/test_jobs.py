"""Jobs, recovery, locks, resources (spec §25, §26, §100, ACC-010/031/094/104/105/106)."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time

import pytest

from acet.domain.enums import JobPriority
from acet.domain.error_codes import AcetError
from acet.domain.state_machines import DomainTransitionError
from acet.jobs import power
from acet.jobs import store as jobs
from acet.jobs.locks import single_flight, try_acquire
from acet.jobs.resources import disk_preflight
from acet.storage.db import Database


def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


@pytest.mark.acceptance("ACC-010")
def test_interrupted_jobs_are_offered_for_resume(ws):
    jid = jobs.create_job(ws.db, "analysis", {"x": 1})
    jobs.transition(ws.db, jid, "PREPARING")
    jobs.transition(ws.db, jid, "RUNNING", owner_pid=_dead_pid(), owner_host=socket.gethostname())
    live = jobs.create_job(ws.db, "analysis", {"x": 2})
    jobs.transition(ws.db, live, "PREPARING")  # owned by this (alive) process
    assert jobs.recover_interrupted(ws.db) == [jid]
    assert jobs.get_job(ws.db, jid)["state"] == "INTERRUPTED"
    assert jobs.get_job(ws.db, jid)["error_code"] == "ACET-JOB-002"
    assert jobs.get_job(ws.db, live)["state"] == "PREPARING"


@pytest.mark.acceptance("ACC-104")
def test_illegal_job_transition_has_no_side_effect(ws):
    jid = jobs.create_job(ws.db, "analysis", {})
    before = dict(jobs.get_job(ws.db, jid))
    with pytest.raises(DomainTransitionError):
        jobs.transition(ws.db, jid, "COMPLETED")
    assert dict(jobs.get_job(ws.db, jid)) == before


def test_priority_aging_prevents_starvation(ws):
    low = jobs.create_job(ws.db, "a", {}, priority=JobPriority.LOW)
    high = jobs.create_job(ws.db, "a", {}, priority=JobPriority.HIGH)
    assert jobs.pick_next(ws.db) == high
    later = time.time() + 60 * 25  # 25 minutes later the old LOW job outranks a fresh HIGH one
    ws.db.conn.execute(
        "UPDATE job SET created_at=? WHERE id=?",
        (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 60 * 24)), high),
    )
    assert jobs.pick_next(ws.db, now=later) == low


@pytest.mark.acceptance("ACC-105")
def test_single_flight_runs_one_heavy_computation(ws):
    computed = []
    cache: dict[str, int] = {}
    start = threading.Barrier(100)

    def worker() -> None:
        db = Database(ws.db.path)
        try:
            start.wait()
            with single_flight(db, "k" * 64, poll_s=0.01):
                if "k" not in cache:
                    time.sleep(0.05)
                    computed.append(1)
                    cache["k"] = 1
        finally:
            db.close()

    threads = [threading.Thread(target=worker) for _ in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(computed) == 1


@pytest.mark.acceptance("ACC-106")
def test_dead_lock_owner_is_recovered(ws):
    with ws.db.transaction() as tx:
        tx.execute("INSERT INTO app_lock VALUES ('flight:x','dead',?,?,'t','t')", (_dead_pid(), socket.gethostname()))
    assert try_acquire(ws.db, "flight:x", "me")
    assert not try_acquire(ws.db, "flight:x", "other")


@pytest.mark.acceptance("ACC-031")
def test_heavy_job_refused_without_disk(tmp_path, monkeypatch):
    import shutil as _sh

    monkeypatch.setattr(_sh, "disk_usage", lambda p: _sh._ntuple_diskusage(10**9, 10**9 - 10, 10))  # type: ignore[attr-defined]
    with pytest.raises(AcetError) as ei:
        disk_preflight(tmp_path, 10**6)
    assert ei.value.code == "ACET-IMP-003"


@pytest.mark.acceptance("ACC-094")
def test_sleep_prevention_always_restored():
    with pytest.raises(RuntimeError), power.keep_awake(True):
        assert power.prevention_active()
        raise RuntimeError("job failed")
    assert not power.prevention_active()
    with power.keep_awake(False):
        assert not power.prevention_active()


def test_killed_after_the_run_finished_closes_the_job_without_redoing_it(ws, product_id):
    """CI repro (ACC-108): the application died between 'run COMPLETED' and 'job COMPLETED'."""
    from pathlib import Path

    from acet.analysis.orchestrator import analyze_build, resume
    from acet.ingest.importer import ImportRequest, import_build

    demo = Path(__file__).resolve().parents[2] / "datasets" / "demo" / "builds" / "v1"
    b = import_build(ws, ImportRequest([demo], product_id)).build_id
    s = analyze_build(ws, b, "FAST@1")
    assert s.status == "COMPLETED"
    with ws.db.transaction() as tx:  # the job row as the kill left it: still RUNNING, owner gone
        tx.execute("UPDATE job SET state='RUNNING', owner_pid=999999, owner_host=? WHERE id=?",
                   (socket.gethostname(), s.job_id))  # fmt: skip
    before = ws.db.conn.execute("SELECT COUNT(*) FROM processor_run WHERE analysis_run_id=?", (s.run_id,)).fetchone()[0]
    assert jobs.recover_interrupted(ws.db) == [s.job_id]
    r = resume(ws, s.job_id)
    assert r.status == "COMPLETED" and r.run_id == s.run_id
    assert jobs.get_job(ws.db, s.job_id)["state"] == "COMPLETED"
    after = ws.db.conn.execute("SELECT COUNT(*) FROM processor_run WHERE analysis_run_id=?", (s.run_id,)).fetchone()[0]
    assert after == before  # nothing re-executed
