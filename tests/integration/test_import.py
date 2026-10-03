"""Import pipeline — nominal path and the hostile matrix of spec §50 (roadmap gate P2)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from acet.application.builds import get_build, list_builds, restore_build, soft_delete_build, verify_build_artifacts
from acet.domain.enums import BuildStatus, ComponentRole, IntegrityState
from acet.domain.error_codes import AcetError
from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build
from acet.platform.doctor import quarantine_orphans, reconcile
from tests.fixtures import build_a, build_b, driver, write_build


def _count(ws, table: str) -> int:
    return ws.db.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def _blobs(ws) -> int:
    return sum(1 for _ in ws.store.iter_blobs())


def test_nominal_import(ws, product_id, tmp_path):
    res = import_build(
        ws, ImportRequest([build_a(tmp_path / "a")], product_id, release_label="1.0", observed_at="2026-09-01")
    )
    assert res.created_build and len(res.new_artifacts) == 4
    assert res.status is BuildStatus.COMPLETE
    b = get_build(ws, res.build_id)
    roles = sorted(c["role"] for c in b["components"])
    assert roles == ["CONFIGURATION", "EXECUTABLE", "KERNEL_DRIVER", "USER_MODULE"]
    assert all(c["integrity_state"] == "AVAILABLE" for c in b["components"])
    assert b["observations"][0]["observed_at"] == "2026-09-01"
    assert b["observations"][0]["time_precision"] == "DAY"
    # Blobs are content-addressed and read-only.
    p = ws.store.path_for(res.new_artifacts[0])
    assert p.read_bytes() and not (p.stat().st_mode & stat.S_IWUSR)
    # Privacy: no absolute source path stored anywhere in the DB (ACET-PRI-001).
    dump = "\n".join(ws.db.conn.iterdump())
    assert str(tmp_path) not in dump


@pytest.mark.acceptance("ACC-047")
def test_profile_completeness_partial_unknown(ws, product_id, tmp_path):
    folder = write_build(tmp_path / "p", {"Fict.sys": driver(b"only-driver")})
    res = import_build(ws, ImportRequest([folder], product_id))
    assert res.status is BuildStatus.PARTIAL
    assert res.completeness == {"KERNEL_DRIVER": "PRESENT", "EXECUTABLE": "UNKNOWN", "USER_MODULE": "UNKNOWN"}
    res_full = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    assert res_full.status is BuildStatus.COMPLETE


@pytest.mark.acceptance("ACC-005")
def test_duplicate_artifact_bytes_not_duplicated(ws, product_id, tmp_path):
    import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    res_b = import_build(ws, ImportRequest([build_b(tmp_path / "b")], product_id))
    assert len(res_b.reused_artifacts) == 2 and len(res_b.new_artifacts) == 2
    assert _blobs(ws) == 6 == _count(ws, "artifact")
    assert not any("near-duplicate" in w for w in res_b.warnings)  # 2/6 shared < threshold
    assert _count(ws, "build") == 2


def test_near_duplicate_warns_but_never_merges(ws, product_id, tmp_path):
    a = build_a(tmp_path / "a")
    first = import_build(ws, ImportRequest([a], product_id))
    near = write_build(tmp_path / "near", {p.name: p.read_bytes() for p in a.iterdir()})
    (near / "Fict.sys").write_bytes(driver(b"hotfix"))
    res = import_build(ws, ImportRequest([near], product_id))
    assert res.created_build and res.build_id != first.build_id  # ACET-IMP-005
    assert any("near-duplicate" in w and first.build_id in w for w in res.warnings)


@pytest.mark.acceptance("ACC-006")
def test_duplicate_build_proposes_observation(ws, product_id, tmp_path):
    a = build_a(tmp_path / "a")
    first = import_build(ws, ImportRequest([a], product_id))
    with pytest.raises(AcetError) as ei:
        import_build(ws, ImportRequest([a], product_id))
    assert ei.value.code == "ACET-IMP-004"
    assert ei.value.data["build_id"] == first.build_id
    assert set(ei.value.data["options"]) == {"add-observation", "open", "cancel"}
    assert _count(ws, "observation") == 1

    # Same bytes copied elsewhere with different names → same technical identity.
    copy = write_build(tmp_path / "renamed", {f"x_{p.name}": p.read_bytes() for p in a.iterdir()})
    second = import_build(
        ws, ImportRequest([copy], product_id, observed_at="2026-10-01", on_duplicate=DuplicatePolicy.ADD_OBSERVATION)
    )
    assert not second.created_build and second.build_id == first.build_id
    assert _count(ws, "build") == 1 and _count(ws, "observation") == 2


@pytest.mark.acceptance("ACC-007", "ACC-082", "ACC-140")
@pytest.mark.parametrize("stage", ["discover", "hashed", "before_commit", "in_commit"])
def test_failure_before_commit_leaves_no_visible_build(ws, product_id, tmp_path, stage):
    def fault(s: str) -> None:
        if s == stage:
            raise OSError(f"injected at {s}")

    with pytest.raises(OSError):
        import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id), fault=fault)
    for table in ("build", "component", "observation", "artifact", "component_artifact"):
        assert _count(ws, table) == 0, table
    rep = reconcile(ws)
    # Blobs copied before the failed commit are detectable orphans, never valid rows.
    assert len(rep.orphan_blobs) == (_blobs(ws))
    assert rep.dangling_refs == []
    if stage in ("before_commit", "in_commit"):
        assert len(rep.orphan_blobs) == 4
        assert quarantine_orphans(ws, rep) == 4
        assert reconcile(ws).clean
        assert len(list((ws.path / "quarantine" / "orphans").iterdir())) == 4


def test_retry_after_failed_commit_succeeds(ws, product_id, tmp_path):
    a = build_a(tmp_path / "a")

    def boom(s: str) -> None:
        if s == "in_commit":
            raise OSError("power loss")

    with pytest.raises(OSError):
        import_build(ws, ImportRequest([a], product_id), fault=boom)
    res = import_build(ws, ImportRequest([a], product_id))
    assert len(res.reused_artifacts) == 4  # bytes already landed; only rows are new
    assert reconcile(ws).clean


def test_source_disappears_during_import(ws, product_id, tmp_path):
    a = build_a(tmp_path / "a")

    def vanish(s: str) -> None:
        if s == "hashed":
            (a / "Fict.sys").unlink()

    with pytest.raises(AcetError) as ei:
        import_build(ws, ImportRequest([a], product_id), fault=vanish)
    assert ei.value.code == "ACET-IMP-001"
    assert _count(ws, "build") == 0


def test_source_modified_between_hash_and_copy(ws, product_id, tmp_path):
    a = build_a(tmp_path / "a")

    def tamper(s: str) -> None:
        if s == "hashed":
            (a / "Fict.sys").write_bytes(driver(b"tampered"))

    with pytest.raises(AcetError) as ei:
        import_build(ws, ImportRequest([a], product_id), fault=tamper)
    assert ei.value.code == "ACET-IMP-002"
    assert _count(ws, "build") == 0
    assert list(ws.store.iter_temp_leftovers()) == []


def test_disk_preflight_refuses(ws, product_id, tmp_path, monkeypatch):
    import shutil as _sh

    monkeypatch.setattr(_sh, "disk_usage", lambda p: _sh._ntuple_diskusage(100, 100, 0))  # type: ignore[attr-defined]
    with pytest.raises(AcetError) as ei:
        import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    assert ei.value.code == "ACET-IMP-003"
    assert _count(ws, "build") == 0 and _blobs(ws) == 0


@pytest.mark.acceptance("ACC-008")
def test_corrupted_artifact_detected_before_analysis(ws, product_id, tmp_path):
    res = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    assert len(verify_build_artifacts(ws, res.build_id)) == 4
    victim = ws.store.path_for(res.new_artifacts[0])
    os.chmod(victim, stat.S_IREAD | stat.S_IWRITE)
    victim.write_bytes(b"bitrot")
    with pytest.raises(AcetError) as ei:
        verify_build_artifacts(ws, res.build_id)
    assert ei.value.code == "ACET-STO-002"
    state = ws.db.conn.execute(
        "SELECT integrity_state FROM artifact WHERE sha256=?", (res.new_artifacts[0],)
    ).fetchone()[0]
    assert state == IntegrityState.CORRUPTED.value
    assert reconcile(ws, deep=True).hash_mismatches == [res.new_artifacts[0]]


def test_reimport_never_reuses_a_corrupted_blob(ws, product_id, tmp_path):
    """Audit repro: corrupt a stored blob, re-import the original bytes → the blob must be
    re-verified, the corrupt copy quarantined (not deleted) and the good bytes restored."""
    src = build_a(tmp_path / "a")
    res = import_build(ws, ImportRequest([src], product_id))
    sha = res.new_artifacts[0]
    victim = ws.store.path_for(sha)
    os.chmod(victim, stat.S_IREAD | stat.S_IWRITE)
    victim.write_bytes(b"evil")
    with pytest.raises(AcetError):
        verify_build_artifacts(ws, res.build_id)

    again = import_build(ws, ImportRequest([src], product_id, on_duplicate=DuplicatePolicy.ADD_OBSERVATION))
    assert ws.store.verify(sha)
    assert victim.read_bytes() != b"evil"
    assert any(sha in w and "corrupted" in w for w in again.warnings)
    quarantined = list((ws.path / "quarantine" / "corrupted").iterdir())
    assert [q.read_bytes() for q in quarantined] == [b"evil"]
    state = ws.db.conn.execute("SELECT integrity_state FROM artifact WHERE sha256=?", (sha,)).fetchone()[0]
    assert state == IntegrityState.AVAILABLE.value
    assert (
        ws.db.conn.execute(
            "SELECT COUNT(*) FROM audit_event WHERE event_type='artifact.repaired' AND target_id=?", (sha,)
        ).fetchone()[0]
        == 1
    )
    assert len(verify_build_artifacts(ws, res.build_id)) == 4


def test_store_put_file_verifies_existing_blob(ws, tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"payload")
    first = ws.store.put_file(f)
    blob = ws.store.path_for(first.sha256)
    os.chmod(blob, stat.S_IREAD | stat.S_IWRITE)
    blob.write_bytes(b"evil")
    second = ws.store.put_file(f)
    assert (second.created, second.repaired) == (False, True)
    assert blob.read_bytes() == b"payload" and ws.store.verify(first.sha256)
    third = ws.store.put_file(f)
    assert (third.created, third.repaired) == (False, False)


@pytest.mark.acceptance("ACC-141", "ACC-037")
def test_reconcile_detects_dangling_reference(ws, product_id, tmp_path):
    res = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    victim = ws.store.path_for(res.new_artifacts[1])
    os.chmod(victim, stat.S_IREAD | stat.S_IWRITE)
    victim.unlink()
    rep = reconcile(ws)
    assert rep.dangling_refs == [res.new_artifacts[1]] and not rep.clean
    with pytest.raises(AcetError) as ei:
        verify_build_artifacts(ws, res.build_id)
    assert ei.value.code == "ACET-STO-001"


@pytest.mark.acceptance("ACC-036", "ACC-035")
def test_soft_delete_is_recoverable_and_audited(ws, product_id, tmp_path):
    res = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    soft_delete_build(ws, res.build_id)
    assert list_builds(ws) == []
    assert _blobs(ws) == 4  # bytes untouched
    restore_build(ws, res.build_id)
    assert [b["id"] for b in list_builds(ws)] == [res.build_id]
    events = [r[0] for r in ws.db.conn.execute("SELECT event_type FROM audit_event ORDER BY id")]
    assert events[-3:] == ["import", "build.soft_delete", "build.restore"]
    assert "product.create" in events


@pytest.mark.acceptance("ACC-064")
def test_unicode_file_names(ws, product_id, tmp_path):
    names = ["Pilote-é.sys", "Драйвер.dll", "驱动程序.exe", "emoji_🛡️.json", "café.cfg"]
    folder = write_build(
        tmp_path / "ünïcødé", {n: driver(n.encode()) if n.endswith(".sys") else n.encode() for n in names}
    )
    res = import_build(ws, ImportRequest([folder], product_id))
    labels = {c["label"] for c in get_build(ws, res.build_id)["components"]}
    assert labels == set(names)


@pytest.mark.acceptance("ACC-065")
@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privilege on Windows CI")
def test_reparse_loop_does_not_hang(ws, product_id, tmp_path):
    folder = build_a(tmp_path / "loop")
    (folder / "sub").mkdir()
    (folder / "sub" / "back").symlink_to(folder, target_is_directory=True)
    (folder / "dangling").symlink_to(tmp_path / "missing")
    res = import_build(ws, ImportRequest([folder], product_id))
    assert len(res.files) == 4
    assert any("loop" in w for w in res.warnings)


def test_role_override_and_unknown_product(ws, product_id, tmp_path):
    a = build_a(tmp_path / "a")
    res = import_build(ws, ImportRequest([a], product_id, role_overrides={"FictSvc.exe": ComponentRole.SERVICE}))
    assert {f["name"]: f["role"] for f in res.files}["FictSvc.exe"] == "SERVICE"
    with pytest.raises(AcetError) as ei:
        import_build(ws, ImportRequest([a], "nope"))
    assert ei.value.code == "ACET-NOTFOUND-001"


def test_import_by_product_name_and_missing_path(ws, product_id, tmp_path):
    res = import_build(ws, ImportRequest([build_a(tmp_path / "a")], "Fictional Guard"))
    assert res.created_build
    with pytest.raises(AcetError) as ei:
        import_build(ws, ImportRequest([Path(tmp_path / "missing")], product_id))
    assert ei.value.code == "ACET-IMP-001"
