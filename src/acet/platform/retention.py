"""Retention, cleanup and purge (spec §80, ACET-STO-003, ACET-RET-001..003, ACC-046/083/084/148).

Every cleanup has a dry run listing exact objects and recoverable bytes. SOURCE
(artifact bytes of live builds) and FACT/current derived results are never part
of cache cleanup. Purge is two-phase (Trash → explicit purge): bytes of artifacts
still referenced by another build are never touched; purged bytes go to
quarantine first and are deleted only after the quarantine retention.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.error_codes import AcetError
from acet.domain.state_machines import ARTIFACT
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo


@dataclass(frozen=True)
class RetentionPolicy:
    temp_days: float = 1
    quarantine_days: float = 30
    log_budget_bytes: int = 1024**3
    backups_daily: int = 7
    backups_weekly: int = 4


@dataclass
class CleanupItem:
    path: str
    bytes: int
    category: str
    reason: str


@dataclass
class CleanupPlan:
    items: list[CleanupItem] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(i.bytes for i in self.items)

    def to_dict(self) -> dict[str, Any]:
        return {"items": [i.__dict__ for i in self.items], "total_bytes": self.total_bytes, "count": len(self.items)}


def _size(p: Path) -> int:
    if p.is_file():
        return p.stat().st_size
    return sum(x.stat().st_size for x in p.rglob("*") if x.is_file())


def _age_days(p: Path) -> float:
    return (time.time() - p.stat().st_mtime) / 86400


def _active_temp(ws: Workspace) -> set[str]:
    rows = ws.db.conn.execute(
        "SELECT id FROM processor_run WHERE status NOT IN ('COMPLETED','PARTIAL','FAILED','SKIPPED')"
    )
    return {r[0] for r in rows}


def plan_cleanup(ws: Workspace, policy: RetentionPolicy | None = None) -> CleanupPlan:
    policy = policy or RetentionPolicy()
    plan = CleanupPlan()

    def rel(p: Path) -> str:
        return p.relative_to(ws.path).as_posix()

    active = _active_temp(ws)
    temp = ws.path / "temp"
    for p in sorted(temp.glob("*")) if temp.is_dir() else []:
        if p.name.endswith(".tmp") or (p.is_dir() and _age_days(p) >= policy.temp_days):
            plan.items.append(CleanupItem(rel(p), _size(p), "temp", "temporary file never valid output"))
    runs = temp / "runs"
    for p in sorted(runs.glob("*")) if runs.is_dir() else []:
        if p.name not in active and _age_days(p) >= policy.temp_days:
            plan.items.append(CleanupItem(rel(p), _size(p), "temp", "stale worker staging directory"))
    logs = sorted((ws.path / "logs" / "processor_runs").glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    used = 0
    for p in logs:
        sz = _size(p)
        used += sz
        if used > policy.log_budget_bytes:
            plan.items.append(CleanupItem(rel(p), sz, "logs", "log budget exceeded (oldest first)"))
    backups = sorted((ws.path / "backups").glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    keep: set[Path] = set(backups[: policy.backups_daily])
    weeks: set[str] = set()
    for p in backups:
        wk = datetime.fromtimestamp(p.stat().st_mtime, UTC).strftime("%G-%V")
        if wk not in weeks and len(weeks) < policy.backups_weekly:
            weeks.add(wk)
            keep.add(p)
    for p in backups:
        if p not in keep:
            plan.items.append(CleanupItem(rel(p), _size(p), "backups", "outside 7 daily + 4 weekly retention"))
    q = ws.path / "quarantine"
    for p in sorted(q.rglob("*")) if q.is_dir() else []:
        if p.is_file() and _age_days(p) >= policy.quarantine_days:
            plan.items.append(CleanupItem(rel(p), _size(p), "quarantine", f"older than {policy.quarantine_days} days"))
    for r in ws.db.conn.execute("SELECT output_relpath FROM derived_result WHERE state IN ('FAILED','CORRUPTED')"):
        p = ws.path / r[0]
        if p.exists():
            plan.items.append(CleanupItem(r[0], _size(p), "cache", "failed/corrupted derived attempt (rebuildable)"))
    for item in plan.items:  # invariant: never SOURCE or current FACT/derived results (ACC-046)
        assert not item.path.startswith("artifacts/"), item.path
    return plan


def apply_cleanup(ws: Workspace, plan: CleanupPlan) -> int:
    ws.require_writable()
    freed = 0
    for item in plan.items:
        p = ws.path / item.path
        if not p.exists():
            continue
        if p.is_dir():
            shutil.rmtree(p)
        else:
            os.chmod(p, 0o600)
            p.unlink()
        freed += item.bytes
        if item.category == "quarantine" and len(p.name) == 64:
            row = ws.db.conn.execute("SELECT integrity_state FROM artifact WHERE sha256=?", (p.name,)).fetchone()
            if row and row[0] == "QUARANTINED":
                with ws.db.transaction() as tx:
                    tx.execute(
                        "UPDATE artifact SET integrity_state='PURGED', purged_at=? WHERE sha256=?",
                        (utc_now_iso(), p.name),
                    )
    with ws.db.transaction() as tx:
        repo.audit(tx, "cleanup.apply", None, None, {"items": len(plan.items), "bytes": freed})
    return freed


def plan_purge(ws: Workspace, build_id: str) -> dict[str, Any]:
    b = ws.db.conn.execute("SELECT deleted_at, purged_at FROM build WHERE id=?", (build_id,)).fetchone()
    if b is None or b["deleted_at"] is None:
        raise AcetError("ACET-NOTFOUND-001", "only builds in the trash can be purged (ACET-RET-001)")
    shas = {r["sha256"] for r in repo.build_artifacts(ws.db.conn, build_id)}
    exclusive, shared, locked = [], [], []
    for sha in sorted(shas):
        others = ws.db.conn.execute(
            "SELECT count(*) FROM component c JOIN component_artifact ca ON ca.component_id=c.id JOIN build b"
            " ON b.id=c.build_id WHERE ca.artifact_sha256=? AND c.build_id<>? AND b.purged_at IS NULL",
            (sha, build_id),
        ).fetchone()[0]
        busy = ws.db.conn.execute(
            "SELECT count(*) FROM job j JOIN analysis_run ar ON ar.id=j.analysis_run_id WHERE j.state IN"
            " ('PREPARING','RUNNING','PAUSING','PAUSED','RESUMING','POST_PROCESSING') AND ar.input_hashes_json LIKE ?",
            (f"%{sha}%",),
        ).fetchone()[0]
        if busy:
            locked.append(sha)
        elif others:
            shared.append(sha)
        else:
            exclusive.append(sha)
    size = sum(
        ws.db.conn.execute("SELECT size_bytes FROM artifact WHERE sha256=?", (s,)).fetchone()[0] for s in exclusive
    )
    return {
        "build_id": build_id,
        "to_quarantine": exclusive,
        "kept_shared": shared,
        "kept_in_use": locked,
        "bytes": size,
    }


def apply_purge(ws: Workspace, build_id: str) -> dict[str, Any]:
    ws.require_writable()
    plan = plan_purge(ws, build_id)
    if plan["kept_in_use"]:
        raise AcetError("ACET-DOM-001", "artifacts are in use by a running job; purge refused (ACC-148)")
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    for sha in plan["to_quarantine"]:
        p = ws.store.path_for(sha)
        with ws.db.transaction() as tx:
            st = tx.execute("SELECT integrity_state FROM artifact WHERE sha256=?", (sha,)).fetchone()[0]
            for nxt in ("ORPHANED", "QUARANTINED"):
                st = ARTIFACT.check(st, nxt)
            tx.execute("UPDATE artifact SET integrity_state=? WHERE sha256=?", (st, sha))
            repo.audit(tx, "artifact.quarantine", "artifact", sha, {"build_id": build_id})
        if p.exists():
            ws.store.quarantine(p, f"purge-{stamp}")
    with ws.db.transaction() as tx:
        tx.execute("UPDATE build SET purged_at=? WHERE id=?", (utc_now_iso(), build_id))
        repo.audit(
            tx,
            "build.purge",
            "build",
            build_id,
            {"quarantined": len(plan["to_quarantine"]), "kept_shared": len(plan["kept_shared"])},
        )
    return plan


def quarantine_expiry(days: float) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()
