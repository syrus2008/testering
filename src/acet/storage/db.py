"""SQLite service (ACET-DB-001..006, ACET-TXN-001).

* ``PRAGMA foreign_keys=ON`` is mandatory and verified on every connection.
* WAL is used unless the filesystem refuses it; any fallback is logged.
* Transactions are explicit and short; their durations are recorded so tests
  can assert that no long external work ran inside one (ACC-107).
* Hot backups use the SQLite Online Backup API — never a naive file copy.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from acet.domain.error_codes import AcetError

log = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = 5000


class Database:
    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        self.journal_mode = "unknown"
        self.tx_durations_ms: list[float] = []
        self.conn = self._connect()

    # -- connection -------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        if self.read_only:
            uri = self.path.resolve().as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=False)
        else:
            conn = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA foreign_keys=ON")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            conn.close()
            raise AcetError("ACET-INT-001", "SQLite build does not support foreign keys (ACET-DB-001)")
        if not self.read_only:
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            self.journal_mode = str(mode).lower()
            if self.journal_mode != "wal":
                log.warning("SQLite WAL unavailable on this filesystem; fallback journal_mode=%s", mode)
            conn.execute("PRAGMA synchronous=FULL")
        else:
            self.journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        return conn

    def close(self) -> None:
        self.conn.close()

    # -- transactions -----------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self.read_only:
            raise AcetError("ACET-DB-003", "workspace is open read-only")
        start = time.perf_counter()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")
        finally:
            self.tx_durations_ms.append((time.perf_counter() - start) * 1000)

    # -- schema -----------------------------------------------------------
    @property
    def user_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()[0])

    # -- integrity --------------------------------------------------------
    def integrity_check(self, *, quick: bool = False) -> list[str]:
        pragma = "quick_check" if quick else "integrity_check"
        try:
            rows = [str(r[0]) for r in self.conn.execute(f"PRAGMA {pragma}").fetchall()]
            fk = self.conn.execute("PRAGMA foreign_key_check").fetchall()
        except sqlite3.DatabaseError as exc:
            # A malformed image may make the check itself raise: that is a finding, not a crash.
            return [f"{pragma}: {exc}"]
        problems = [] if rows == ["ok"] else rows
        problems += [f"foreign_key_check: {tuple(r)}" for r in fk]
        return problems

    def checkpoint(self) -> None:
        """ACET-DB-005: explicit checkpoint before file-snapshot operations."""
        if self.journal_mode == "wal":
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # -- backup -----------------------------------------------------------
    def backup_to(self, dest: Path) -> Path:
        """WAL-aware hot backup via the Online Backup API (ACET-DB-004)."""
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        if tmp.exists():
            tmp.unlink()
        target = sqlite3.connect(str(tmp))
        try:
            self.conn.backup(target)
            ok = target.execute("PRAGMA integrity_check").fetchone()[0]
            # Backups are standalone files: switch them out of WAL.
            target.execute("PRAGMA journal_mode=DELETE")
        finally:
            target.close()
        if ok != "ok":
            tmp.unlink(missing_ok=True)
            raise AcetError("ACET-DB-001", "backup failed integrity_check")
        os.replace(tmp, dest)
        return dest


def restore_file(backup: Path, active: Path) -> None:
    """ACET-DB-006: temp copy → integrity_check → atomic swap. Caller holds the workspace lock
    and has closed every connection to ``active``."""
    import shutil

    tmp = active.with_name(active.name + ".restore.tmp")
    shutil.copyfile(backup, tmp)
    conn = sqlite3.connect(str(tmp))
    try:
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()
    if ok != "ok":
        tmp.unlink(missing_ok=True)
        raise AcetError("ACET-DB-001", "backup to restore is not intact; active DB left untouched")
    for suffix in ("-wal", "-shm"):
        Path(str(active) + suffix).unlink(missing_ok=True)
    os.replace(tmp, active)
