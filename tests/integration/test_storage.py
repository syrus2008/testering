from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from acet.application.workspace import WorkspaceMode, create_workspace, open_workspace
from acet.domain.error_codes import AcetError
from acet.storage.db import Database, restore_file
from acet.storage.migrations import LATEST_SCHEMA_VERSION, Migration, load_migrations
from acet.storage.migrator import migrate, split_statements


def test_foreign_keys_and_wal(ws):
    assert ws.db.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert ws.db.journal_mode == "wal"
    with pytest.raises(sqlite3.IntegrityError), ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO product(id, workspace_id, name, profile_json, created_at) VALUES ('p','nope','n','{}','t')"
        )


def test_workspace_layout(ws):
    for sub in ("artifacts", "derived", "reports", "exports", "backups", "logs", "temp", "quarantine"):
        assert (ws.path / sub).is_dir()
    assert ws.db.user_version == LATEST_SCHEMA_VERSION


def test_schema_indexes_present(ws):
    names = {r[0] for r in ws.db.conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    for ix in (
        "ix_observation_build_observed",
        "ix_component_build_role",
        "ix_function_instance_artifact_address",
        "ix_matcher_result_run_engine_decision",
        "ix_lineage_assignment_lineage_run",
        "ix_job_state_priority_created",
        "ix_external_event_product_occurred",
    ):
        assert ix in names


@pytest.mark.acceptance("ACC-035")
def test_audit_is_append_only(ws):
    with pytest.raises(sqlite3.IntegrityError), ws.db.transaction() as tx:
        tx.execute("UPDATE audit_event SET event_type='x'")
    with pytest.raises(sqlite3.IntegrityError), ws.db.transaction() as tx:
        tx.execute("DELETE FROM audit_event")
    assert ws.db.conn.execute("SELECT count(*) FROM audit_event WHERE event_type='workspace.create'").fetchone()[0] == 1


def test_split_statements_handles_triggers():
    sql = "CREATE TABLE t(a);\n-- c\nCREATE TRIGGER x BEFORE UPDATE ON t\nBEGIN SELECT 1; SELECT 2; END;\n"
    assert len(list(split_statements(sql))) == 2


@pytest.mark.acceptance("ACC-024", "ACC-130")
def test_migration_failure_rolls_back_atomically(tmp_path: Path):
    db = Database(tmp_path / "acet.db")
    base = load_migrations()
    migrate(db, tmp_path / "backups", migrations=base)
    with db.transaction() as tx:
        tx.execute("INSERT INTO workspace VALUES ('w','n','t',1)")
    bad = Migration(2, "0002_bad.sql", "ALTER TABLE build ADD COLUMN extra TEXT;\nCREATE TABLE broken (;\n")
    with pytest.raises(AcetError) as ei:
        migrate(db, tmp_path / "backups", migrations=[*base, bad])
    assert ei.value.code == "ACET-DB-002"
    assert db.user_version == 1
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(build)")}
    assert "extra" not in cols
    assert db.conn.execute("SELECT count(*) FROM workspace").fetchone()[0] == 1
    assert list((tmp_path / "backups").glob("pre-migration-v0001-*.db"))

    good = Migration(2, "0002_good.sql", "ALTER TABLE build ADD COLUMN extra TEXT;\n")
    assert migrate(db, tmp_path / "backups", migrations=[*base, good]) == 2
    assert "extra" in {r[1] for r in db.conn.execute("PRAGMA table_info(build)")}
    db.close()


@pytest.mark.acceptance("ACC-129")
def test_old_app_refuses_write_on_future_schema(ws):
    path = ws.path
    ws.db.conn.execute(f"PRAGMA user_version={LATEST_SCHEMA_VERSION + 1}")
    ws.close()
    with pytest.raises(AcetError) as ei:
        open_workspace(path)
    assert ei.value.code == "ACET-DB-003"
    ro = open_workspace(path, read_only=True)
    try:
        assert ro.mode is WorkspaceMode.READ_ONLY
        with pytest.raises(AcetError):
            ro.require_writable()
    finally:
        ro.close()


@pytest.mark.acceptance("ACC-055", "ACC-045")
def test_hot_backup_during_concurrent_writes_is_consistent(ws, product_id, tmp_path):
    stop = threading.Event()
    db2 = Database(ws.db.path)

    def writer():
        i = 0
        while not stop.is_set():
            with db2.transaction() as tx:
                tx.execute(
                    "INSERT INTO annotation(id, target_type, target_id, body, created_at) VALUES (?,?,?,?,?)",
                    (f"a{i}", "product", product_id, "note", "t"),
                )
            i += 1

    t = threading.Thread(target=writer)
    t.start()
    try:
        dest = ws.db.backup_to(tmp_path / "b" / "snap.db")
    finally:
        stop.set()
        t.join()
        db2.close()
    snap = sqlite3.connect(dest)
    assert snap.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert snap.execute("SELECT count(*) FROM product").fetchone()[0] == 1
    snap.close()


@pytest.mark.acceptance("ACC-081")
def test_invalid_restore_never_replaces_active_db(ws, tmp_path):
    bogus = tmp_path / "bogus.db"
    bogus.write_bytes(b"SQLite format 3\x00" + b"\xff" * 4096)
    active = ws.db.path
    ws.close()
    before = active.read_bytes()
    with pytest.raises(Exception):  # noqa: B017 - either sqlite3.DatabaseError or AcetError
        restore_file(bogus, active)
    assert active.read_bytes() == before


@pytest.mark.acceptance("ACC-128")
def test_corrupt_db_opens_recovery_read_only(tmp_path):
    ws = create_workspace("x", tmp_path)
    path = ws.path
    ws.db.checkpoint()
    root = ws.db.conn.execute("SELECT rootpage FROM sqlite_master WHERE name='audit_event'").fetchone()[0]
    page = ws.db.conn.execute("PRAGMA page_size").fetchone()[0]
    ws.close()
    dbf = path / "acet.db"
    for suf in ("-wal", "-shm"):
        Path(str(dbf) + suf).unlink(missing_ok=True)
    data = bytearray(dbf.read_bytes())
    # Corrupt the b-tree page of a populated table (not the schema page): invalid page type byte.
    data[(root - 1) * page] = 0x7F
    dbf.write_bytes(bytes(data))
    try:
        w2 = open_workspace(path)
    except sqlite3.DatabaseError:  # pragma: no cover
        pytest.fail("a data-page corruption must not prevent opening in recovery mode")
    try:
        assert w2.mode is WorkspaceMode.RECOVERY_READ_ONLY
        assert w2.problems
        with pytest.raises(AcetError):
            w2.require_writable()
    finally:
        w2.close()
