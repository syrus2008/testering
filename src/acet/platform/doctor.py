"""Doctor and reconcile (spec §38, ACC-037, ACC-082, ACC-140, ACC-141).

Reconcile is read-only by default: it reports and never "repairs" by deleting
unknown data (§114). Moving orphans to quarantine is an explicit action.
"""

from __future__ import annotations

import os
import platform as _platform
import shutil
import sqlite3
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import acet
from acet.application.workspace import Workspace
from acet.domain.enums import SystemHealth


class CheckStatus(StrEnum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    NOT_AVAILABLE = "NOT_AVAILABLE"  # optional capability absent (DEGRADED, not failure)


@dataclass
class Check:
    name: str
    status: CheckStatus
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            **({"data": self.data} if self.data else {}),
        }


@dataclass
class ReconcileReport:
    orphan_blobs: list[str] = field(default_factory=list)  # blob on disk, no DB row (ACC-140)
    dangling_refs: list[str] = field(default_factory=list)  # DB row, no blob (ACC-141)
    misplaced_blobs: list[str] = field(default_factory=list)  # file name not a SHA or wrong shard
    temp_leftovers: int = 0  # *.tmp never treated as output (ACC-095)
    hash_mismatches: list[str] = field(default_factory=list)  # only with deep=True

    @property
    def clean(self) -> bool:
        return not (self.orphan_blobs or self.dangling_refs or self.misplaced_blobs or self.hash_mismatches)

    def to_dict(self) -> dict[str, Any]:
        return {
            "orphan_blobs": self.orphan_blobs,
            "dangling_refs": self.dangling_refs,
            "misplaced_blobs": self.misplaced_blobs,
            "temp_leftovers": self.temp_leftovers,
            "hash_mismatches": self.hash_mismatches,
            "clean": self.clean,
        }


def reconcile(ws: Workspace, *, deep: bool = False) -> ReconcileReport:
    rep = ReconcileReport()
    db_rows = {
        r["sha256"]: r["integrity_state"]
        for r in ws.db.conn.execute(
            "SELECT sha256, integrity_state FROM artifact WHERE integrity_state NOT IN ('PURGED','METADATA_ONLY','QUARANTINED')"
        )
    }
    on_disk: set[str] = set()
    for name, path in ws.store.iter_blobs():
        try:
            expected = ws.store.path_for(name)
        except ValueError:
            rep.misplaced_blobs.append(path.relative_to(ws.path).as_posix())
            continue
        if expected != path:
            rep.misplaced_blobs.append(path.relative_to(ws.path).as_posix())
            continue
        on_disk.add(name)
    rep.orphan_blobs = sorted(on_disk - set(db_rows))
    rep.dangling_refs = sorted(sha for sha in db_rows if sha not in on_disk)
    rep.temp_leftovers = sum(1 for _ in ws.store.iter_temp_leftovers())
    if deep:
        rep.hash_mismatches = sorted(sha for sha in on_disk & set(db_rows) if not ws.store.verify(sha))
    return rep


def quarantine_orphans(ws: Workspace, report: ReconcileReport) -> int:
    """Explicit action: move orphan blobs to quarantine (ACET-STO-003). Never deletes."""
    n = 0
    for sha in report.orphan_blobs:
        p = ws.store.path_for(sha)
        if p.exists():
            ws.store.quarantine(p, "orphans")
            n += 1
    return n


def system_checks() -> list[Check]:
    checks = [
        Check("python", CheckStatus.OK, sys.version.split()[0]),
        Check(
            "platform",
            CheckStatus.OK if sys.platform == "win32" else CheckStatus.WARN,
            f"{_platform.system()} {_platform.release()}",
            {"supported": "Windows 10/11 x64 (V1 matrix)"} if sys.platform != "win32" else {},
        ),
        Check("sqlite", CheckStatus.OK, sqlite3.sqlite_version),
        Check("acet", CheckStatus.OK, acet.__version__),
    ]
    java = shutil.which("java")
    checks.append(
        Check("java", CheckStatus.OK if java else CheckStatus.NOT_AVAILABLE, "found" if java else "not found")
    )
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR")
    ok = bool(ghidra and (Path(ghidra) / "support").is_dir())
    checks.append(
        Check(
            "ghidra",
            CheckStatus.OK if ok else CheckStatus.NOT_AVAILABLE,
            "detected" if ok else "no Engine Pack / GHIDRA_INSTALL_DIR (roadmap P5)",
        )
    )
    for name in ("ghidriff", "bindiff", "qbindiff"):
        found = shutil.which(name)
        checks.append(
            Check(
                name,
                CheckStatus.OK if found else CheckStatus.NOT_AVAILABLE,
                "detected (unverified)" if found else "not installed",
            )
        )
    checks.append(
        Check("diaphora", CheckStatus.NOT_AVAILABLE, "external IDA-based provider; detection only (ADR-0009)")
    )
    return checks


def workspace_checks(ws: Workspace, *, full: bool = False) -> tuple[list[Check], ReconcileReport]:
    checks: list[Check] = []
    problems = ws.problems or ws.db.integrity_check(quick=not full)
    checks.append(
        Check(
            "database.integrity",
            CheckStatus.FAIL if problems else CheckStatus.OK,
            "; ".join(problems[:3]) if problems else "ok",
            {"mode": ws.mode.value},
        )
    )
    checks.append(
        Check(
            "database.journal_mode",
            CheckStatus.OK if ws.db.journal_mode == "wal" or not ws.writable else CheckStatus.WARN,
            ws.db.journal_mode,
        )
    )
    rec = reconcile(ws, deep=full)
    checks.append(
        Check(
            "artifact_store.reconcile",
            CheckStatus.OK if rec.clean else CheckStatus.FAIL,
            "clean" if rec.clean else "inconsistencies found",
            rec.to_dict(),
        )
    )
    usage = shutil.disk_usage(ws.path)
    free_ratio = usage.free / usage.total if usage.total else 0.0
    checks.append(
        Check(
            "disk",
            CheckStatus.OK if free_ratio > 0.05 else CheckStatus.WARN,
            f"{usage.free // (1024 * 1024)} MiB free",
            {"free_bytes": usage.free},
        )
    )
    temp_probe = ws.path / "temp" / ".doctor-write-probe"
    try:
        temp_probe.write_bytes(b"ok")
        temp_probe.unlink()
        checks.append(Check("disk.permissions", CheckStatus.OK, "workspace temp writable"))
    except OSError as exc:
        checks.append(Check("disk.permissions", CheckStatus.FAIL, type(exc).__name__))
    return checks, rec


def overall_health(checks: list[Check]) -> SystemHealth:
    if any(c.status is CheckStatus.FAIL for c in checks):
        return SystemHealth.ACTION_REQUIRED
    if any(c.status in (CheckStatus.NOT_AVAILABLE, CheckStatus.WARN) for c in checks):
        return SystemHealth.DEGRADED
    return SystemHealth.READY
