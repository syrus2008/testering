"""Workspace lifecycle: create, open (with schema/integrity gates), close."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso
from acet.platform.paths import DB_FILENAME, WORKSPACE_SUBDIRS, workspaces_root
from acet.storage import repositories as repo
from acet.storage.content_store import ContentStore
from acet.storage.db import Database
from acet.storage.migrations import LATEST_SCHEMA_VERSION
from acet.storage.migrator import migrate

log = logging.getLogger(__name__)


class WorkspaceMode(StrEnum):
    READ_WRITE = "READ_WRITE"
    READ_ONLY = "READ_ONLY"
    RECOVERY_READ_ONLY = "RECOVERY_READ_ONLY"  # ACET-DR-001


@dataclass
class Workspace:
    path: Path
    db: Database
    store: ContentStore
    mode: WorkspaceMode
    id: str = ""
    name: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def writable(self) -> bool:
        return self.mode is WorkspaceMode.READ_WRITE

    def require_writable(self) -> None:
        if not self.writable:
            raise AcetError("ACET-DB-003", f"workspace is {self.mode.value}")

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def create_workspace(name: str, parent: Path | None = None) -> Workspace:
    if not name.strip():
        raise AcetError("ACET-WS-001", "workspace name is required")
    wid = uuid7()
    root = (Path(parent) if parent else workspaces_root()).resolve()
    path = root / wid
    path.mkdir(parents=True, exist_ok=False)
    for sub in WORKSPACE_SUBDIRS:
        (path / sub).mkdir()
    db = Database(path / DB_FILENAME)
    migrate(db, path / "backups")
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO workspace(id, name, created_at, schema_version) VALUES (?,?,?,?)",
            (wid, name, utc_now_iso(), db.user_version),
        )
        repo.audit(conn, "workspace.create", "workspace", wid, {"name": name})
    (path / "workspace.json").write_text(json.dumps({"id": wid, "name": name}, indent=2), encoding="utf-8")
    return Workspace(path, db, ContentStore(path), WorkspaceMode.READ_WRITE, wid, name)


def open_workspace(path: Path, *, read_only: bool = False, auto_migrate: bool = True) -> Workspace:
    path = Path(path).resolve()
    dbfile = path / DB_FILENAME
    if not dbfile.is_file():
        raise AcetError("ACET-WS-001", f"no {DB_FILENAME} in workspace")

    probe = Database(dbfile, read_only=True)
    try:
        version = probe.user_version
        problems = probe.integrity_check(quick=True)
    finally:
        probe.close()

    mode = WorkspaceMode.READ_ONLY if read_only else WorkspaceMode.READ_WRITE
    # Old app / new DB: refuse read-write (§115, ACC-129).
    if version > LATEST_SCHEMA_VERSION and not read_only:
        raise AcetError("ACET-DB-003", f"schema v{version} > supported v{LATEST_SCHEMA_VERSION}")
    if problems:
        log.error("workspace integrity check failed; opening RECOVERY_READ_ONLY")
        mode = WorkspaceMode.RECOVERY_READ_ONLY

    db = Database(dbfile, read_only=mode is not WorkspaceMode.READ_WRITE)
    if mode is WorkspaceMode.READ_WRITE and auto_migrate and version < LATEST_SCHEMA_VERSION:
        migrate(db, path / "backups")
        with db.transaction() as conn:
            conn.execute("UPDATE workspace SET schema_version=?", (db.user_version,))
            repo.audit(conn, "workspace.migrate", None, None, {"from": version, "to": db.user_version})

    ws = Workspace(path, db, ContentStore(path), mode, problems=problems)
    row = db.conn.execute("SELECT id, name FROM workspace LIMIT 1").fetchone() if not problems else None
    if row:
        ws.id, ws.name = row["id"], row["name"]
    return ws
