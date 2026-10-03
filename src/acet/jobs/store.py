"""Durable job records with the canonical JOB state machine (§25, ACET-JOB-001..004, ACC-010)."""

from __future__ import annotations

import os
import socket
import time
from datetime import UTC, datetime
from typing import Any

from acet.domain.canonical import stable_json
from acet.domain.enums import JobPriority
from acet.domain.ids import uuid7
from acet.domain.state_machines import ANALYSIS_RUN, JOB
from acet.domain.timeutil import utc_now_iso
from acet.jobs.locks import pid_alive
from acet.storage import repositories as repo
from acet.storage.db import Database

PRIORITY_VALUE = {JobPriority.LOW: 0, JobPriority.NORMAL: 10, JobPriority.HIGH: 20, JobPriority.INTERACTIVE: 30}
AGING_POINTS_PER_MINUTE = 1  # anti-starvation (ACET-JOB-004)
ACTIVE_STATES = ("PREPARING", "RUNNING", "PAUSING", "RESUMING", "POST_PROCESSING")
RESUMABLE_STATES = ("INTERRUPTED", "PAUSED", "FAILED_RETRYABLE")


def create_job(
    db: Database,
    job_type: str,
    payload: dict[str, Any],
    *,
    priority: JobPriority = JobPriority.NORMAL,
    analysis_run_id: str | None = None,
) -> str:
    jid = uuid7()
    now = utc_now_iso()
    with db.transaction() as tx:
        tx.execute(
            "INSERT INTO job(id, job_type, analysis_run_id, state, priority, created_at, updated_at, payload_json, seq)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                jid,
                job_type,
                analysis_run_id,
                JOB.initial,
                PRIORITY_VALUE[priority],
                now,
                now,
                stable_json(payload).decode(),
                repo.next_seq(tx),
            ),
        )
        repo.audit(tx, "job.create", "job", jid, {"job_type": job_type})
    return jid


def get_job(db: Database, job_id: str) -> dict[str, Any] | None:
    return repo.row_to_dict(db.conn.execute("SELECT * FROM job WHERE id=?", (job_id,)).fetchone())


def transition(db: Database, job_id: str, dst: str, **fields: Any) -> None:
    """Validate then persist; an illegal transition raises before any write (ACC-104)."""
    with db.transaction() as tx:
        row = tx.execute("SELECT state FROM job WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        JOB.check(row["state"], dst)
        sets = {"state": dst, "updated_at": utc_now_iso(), **fields}
        if dst in ACTIVE_STATES:
            sets.setdefault("owner_pid", os.getpid())
            sets.setdefault("owner_host", socket.gethostname())
        cols = ", ".join(f"{k}=?" for k in sets)
        tx.execute(f"UPDATE job SET {cols} WHERE id=?", (*sets.values(), job_id))


def checkpoint(
    db: Database, job_id: str, data: dict[str, Any], *, stage: str | None = None, progress: float | None = None
) -> None:
    """ACET-JOB-001: each durable step writes a transactional checkpoint."""
    with db.transaction() as tx:
        tx.execute(
            "UPDATE job SET checkpoint_json=?, stage=COALESCE(?, stage), progress=COALESCE(?, progress),"
            " heartbeat_at=?, updated_at=? WHERE id=?",
            (stable_json(data).decode(), stage, progress, utc_now_iso(), utc_now_iso(), job_id),
        )


def request(db: Database, job_id: str, what: str) -> None:
    """Cooperative pause/cancel/resume requests from UI/CLI."""
    job = get_job(db, job_id)
    if job is None:
        raise KeyError(job_id)
    state = job["state"]
    if what == "cancel":
        if state in ("QUEUED", "PREPARING", "RUNNING", "PAUSING", "PAUSED", "BLOCKED_DEPENDENCY", "HUNG"):
            transition(db, job_id, "CANCELLING")
            if state in ("QUEUED", "PAUSED", "BLOCKED_DEPENDENCY") or not _owner_alive(job):
                transition(db, job_id, "CANCELLED")
        elif state in ("INTERRUPTED",):
            transition(db, job_id, "RECOVERING")
            transition(db, job_id, "FAILED_PERMANENT", error_code="ACET-JOB-002")
        else:
            JOB.check(state, "CANCELLING")
    elif what == "pause":
        transition(db, job_id, "PAUSING")
    else:
        raise ValueError(what)


def _owner_alive(job: dict[str, Any]) -> bool:
    return (
        bool(job.get("owner_pid"))
        and job.get("owner_host") == socket.gethostname()
        and pid_alive(int(job["owner_pid"]))
    )


def recover_interrupted(db: Database) -> list[str]:
    """Startup recovery (ACC-010): jobs whose owner died become INTERRUPTED and are offered for resume."""
    recovered: list[str] = []
    rows = db.conn.execute(
        f"SELECT * FROM job WHERE state IN ({','.join('?' * (len(ACTIVE_STATES) + 2))})",
        (*ACTIVE_STATES, "CANCELLING", "HUNG"),
    ).fetchall()
    for r in rows:
        job = dict(r)
        if _owner_alive(job):
            continue
        if job["state"] == "CANCELLING":
            transition(db, job["id"], "CANCELLED")
            continue
        if job["state"] == "HUNG":
            transition(db, job["id"], "FAILED_RETRYABLE", error_code="ACET-JOB-001")
            continue
        transition(db, job["id"], "INTERRUPTED", error_code="ACET-JOB-002")
        recovered.append(job["id"])
        if job["analysis_run_id"]:
            run = db.conn.execute("SELECT status FROM analysis_run WHERE id=?", (job["analysis_run_id"],)).fetchone()
            if run and ANALYSIS_RUN.can(run["status"], "INTERRUPTED"):
                with db.transaction() as tx:
                    tx.execute("UPDATE analysis_run SET status='INTERRUPTED' WHERE id=?", (job["analysis_run_id"],))
    if recovered:
        with db.transaction() as tx:
            repo.audit(tx, "jobs.recovered", None, None, {"count": len(recovered)})
    return recovered


def effective_priority(priority: int, created_at: str, now: float | None = None) -> float:
    created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    age_min = max(0.0, ((now or time.time()) - created.replace(tzinfo=UTC).timestamp()) / 60)
    return priority + age_min * AGING_POINTS_PER_MINUTE


def pick_next(db: Database, now: float | None = None) -> str | None:
    rows = db.conn.execute("SELECT id, priority, created_at, seq FROM job WHERE state='QUEUED'").fetchall()
    if not rows:
        return None
    best = max(rows, key=lambda r: (effective_priority(r["priority"], r["created_at"], now), -(r["seq"] or 0)))
    return str(best["id"])


def list_jobs(db: Database, *, active_only: bool = False) -> list[dict[str, Any]]:
    sql = (
        "SELECT id, job_type, state, stage, progress, priority, attempts, analysis_run_id, error_code, created_at,"
        " updated_at FROM job"
    )
    if active_only:
        sql += " WHERE state NOT IN ('COMPLETED','CANCELLED','FAILED_PERMANENT')"
    return [dict(r) for r in db.conn.execute(sql + " ORDER BY seq")]
