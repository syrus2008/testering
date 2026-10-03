"""Migration runner (ACET-DB-003, ACET-UPD-003, ACC-024, ACC-129/130).

backup → single transaction applying all pending migrations → integrity_check
→ commit. Any failure rolls back; if the database is not provably back to its
previous state, it is restored from the pre-migration backup.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator, Sequence
from pathlib import Path

from acet.domain.error_codes import AcetError
from acet.domain.timeutil import utc_now_iso
from acet.storage.db import Database, restore_file
from acet.storage.migrations import Migration, load_migrations

log = logging.getLogger(__name__)


def split_statements(sql: str) -> Iterator[str]:
    """Split a script into complete statements (trigger bodies included)."""
    buf: list[str] = []
    for line in sql.splitlines(keepends=True):
        buf.append(line)
        candidate = "".join(buf)
        if sqlite3.complete_statement(candidate):
            stmt = candidate.strip()
            if stmt and not all(ln.strip().startswith("--") or not ln.strip() for ln in stmt.splitlines()):
                yield stmt
            buf = []
    rest = "".join(buf).strip()
    if rest and not all(ln.strip().startswith("--") or not ln.strip() for ln in rest.splitlines()):
        raise ValueError(f"incomplete SQL statement at end of migration: {rest[:80]!r}")


def migrate(
    db: Database,
    backups_dir: Path,
    *,
    migrations: Sequence[Migration] | None = None,
) -> int:
    """Bring ``db`` to the latest schema version; return the resulting version."""
    migs = list(migrations) if migrations is not None else load_migrations()
    latest = migs[-1].version if migs else 0
    current = db.user_version
    if current > latest:
        raise AcetError("ACET-DB-003", f"database schema v{current} > supported v{latest}")
    pending = [m for m in migs if m.version > current]
    if not pending:
        return current

    backup: Path | None = None
    if current > 0:
        stamp = utc_now_iso().replace(":", "").replace("-", "").replace(".", "")
        backup = db.backup_to(backups_dir / f"pre-migration-v{current:04d}-{stamp}.db")
        log.info("pre-migration backup written: %s", backup.name)

    conn = db.conn
    try:
        conn.execute("BEGIN IMMEDIATE")
        for mig in pending:
            for stmt in split_statements(mig.sql):
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version={int(mig.version)}")
        problems = db.integrity_check()
        if problems:
            raise AcetError("ACET-DB-002", f"post-migration integrity_check failed: {problems[:3]}")
        conn.execute("COMMIT")
    except BaseException as exc:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        if db.user_version != current or db.integrity_check():
            if backup is None:
                raise AcetError("ACET-DB-002", "migration failed on a fresh database") from exc
            log.error("rollback incomplete; restoring pre-migration backup")
            db.close()
            restore_file(backup, db.path)
            db.conn = db._connect()
        if isinstance(exc, AcetError) and exc.code == "ACET-DB-002":
            raise
        raise AcetError("ACET-DB-002", f"{type(exc).__name__}: {exc}") from exc
    return db.user_version
