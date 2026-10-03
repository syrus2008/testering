"""Metadata backup and validated restore (spec §63, ACET-DB-004/006, ACC-045/081).

Backups contain the database (results, annotations, settings) only: artifacts are
content-addressed and never duplicated into backups.
"""

from __future__ import annotations

from pathlib import Path

from acet.application.workspace import Workspace, open_workspace
from acet.domain.error_codes import AcetError
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo
from acet.storage.db import restore_file


def backup_metadata(ws: Workspace, dest: Path | None = None) -> Path:
    stamp = utc_now_iso().replace(":", "").replace("-", "").replace(".", "")
    dest = dest or ws.path / "backups" / f"metadata-{stamp}.db"
    if ws.writable:
        ws.db.checkpoint()
    out = ws.db.backup_to(dest)
    if ws.writable:
        with ws.db.transaction() as tx:
            repo.audit(tx, "backup.create", None, None, {"file": out.name})
    return out


def restore_metadata(ws: Workspace, backup: Path) -> Workspace:
    """Exclusive operation: refuses while jobs run; the active DB is replaced only by a valid copy."""
    active = ws.db.conn.execute(
        "SELECT count(*) FROM job WHERE state IN ('PREPARING','RUNNING','PAUSING','RESUMING','POST_PROCESSING')"
    ).fetchone()[0]
    if active:
        raise AcetError("ACET-DOM-001", "jobs are running; restore refused")
    path, dbfile = ws.path, ws.db.path
    ws.close()
    restore_file(backup, dbfile)  # temp copy → integrity_check → atomic swap (ACC-081)
    restored = open_workspace(path)
    with restored.db.transaction() as tx:
        repo.audit(tx, "backup.restore", None, None, {"file": backup.name})
    return restored
