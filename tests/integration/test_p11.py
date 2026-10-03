"""Reports, .acetpack, diagnostics, retention/purge, backup/restore, search, settings (P11)."""

from __future__ import annotations

import hashlib
import json
import sys
import time
import zipfile
from pathlib import Path

import pytest

from acet.analysis.orchestrator import compare_builds
from acet.application.annotations import add_annotation, add_assertion, delete_annotation
from acet.application.backup import backup_metadata, restore_metadata
from acet.application.builds import soft_delete_build
from acet.application.products import create_product
from acet.application.search import rebuild_indexes, search
from acet.application.settings import set_setting
from acet.application.workspace import create_workspace
from acet.changes.detector import detect_changes
from acet.domain.error_codes import AcetError
from acet.domain.jsonschema import validate_named
from acet.ingest.importer import ImportRequest, import_build
from acet.lineage.builder import build_lineage
from acet.platform.diagnostics import create_diagnostic_package
from acet.platform.doctor import reconcile
from acet.platform.retention import apply_cleanup, apply_purge, plan_cleanup, plan_purge
from acet.reporting.acetpack import ArchiveLimits, create_pack, import_pack
from acet.reporting.model import compare_report
from acet.reporting.render import to_csv, to_html, to_markdown, write_report
from tests.fixtures import build_a, driver, write_build

DEMO = Path(__file__).resolve().parents[2] / "datasets" / "demo"


@pytest.fixture
def analysed(ws, product_id, monkeypatch):
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DEMO / "golden" / "ghidra"))
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON"):
        monkeypatch.delenv(k, raising=False)
    b = [
        import_build(
            ws,
            ImportRequest([DEMO / "builds" / f"v{v}"], product_id, release_label=f"v{v}", observed_at=f"2026-0{v}-01"),
        ).build_id
        for v in (1, 2)
    ]
    run = compare_builds(ws, b[0], b[1], "STANDARD@1")
    detect_changes(ws, run.run_id)
    build_lineage(ws, product_id, b)
    return b, run.run_id


@pytest.mark.acceptance("ACC-021", "ACC-028", "ACC-016")
def test_report_validates_and_renders_offline(ws, analysed, tmp_path):
    _b, run = analysed
    rep = compare_report(ws, run)
    validate_named(rep, "report")
    assert rep["executive"]["no_global_score"] is True
    assert all(f["probability"] is None for f in rep["technical"]["functions"])
    assert all(c["measurement"]["state"] for c in rep["technical"]["changes"])
    assert rep["sensitive_content_included"] is False
    assert not any("strings_added" in c["measurement"]["value"] for c in rep["technical"]["changes"])
    html_ = to_html(rep)
    assert "<script" not in html_ and "http://" not in html_ and "https://" not in html_
    assert "obfuscate_buffer" in to_markdown(rep) or "EXACT" in to_markdown(rep)
    assert to_csv(rep).startswith("left_artifact,")
    for fmt in ("json", "html", "md", "csv"):
        p = write_report(rep, fmt, tmp_path / f"r.{fmt}")
        assert p.stat().st_size > 100 and not list(tmp_path.glob("*.tmp"))
    validate_named(json.loads((tmp_path / "r.json").read_text()), "report")


@pytest.mark.acceptance("ACC-022")
def test_pack_without_artifacts_reimports_results_and_annotations(ws, analysed, tmp_path):
    _b, run = analysed
    add_annotation(ws, "analysis_run", run, "Reviewed by analyst: rename confirmed — café ✓")
    pack = create_pack(ws, tmp_path / "x.acetpack")
    with zipfile.ZipFile(pack) as z:
        assert not any(n.startswith("artifacts/") for n in z.namelist())  # opt-in only (ACET-EXP-001)
    ws2 = create_workspace("other", tmp_path / "w2")
    try:
        res = import_pack(ws2, pack)
        assert res["rows_inserted"]["consensus_match"] > 0 and res["rows_inserted"]["annotation"] == 1
        states = {r[0] for r in ws2.db.conn.execute("SELECT DISTINCT integrity_state FROM artifact")}
        assert states == {"METADATA_ONLY"}
        assert reconcile(ws2).clean
        assert search(ws2, "café")[0]["kind"] == "annotation"
        rep = compare_report(ws2, run)
        assert rep["technical"]["functions"]
        assert ws2.db.integrity_check() == []
    finally:
        ws2.close()


@pytest.mark.acceptance("ACC-114")
def test_pack_roundtrip_preserves_canonical_hashes(ws, analysed, tmp_path):
    p1 = create_pack(ws, tmp_path / "a.acetpack", include_artifacts=True)
    ws2 = create_workspace("rt", tmp_path / "w2")
    try:
        import_pack(ws2, p1)
        p2 = create_pack(ws2, tmp_path / "b.acetpack", include_artifacts=True)
    finally:
        ws2.close()

    def digests(p: Path) -> dict[str, str]:
        with zipfile.ZipFile(p) as z:
            m = json.loads(z.read("manifest.json"))
        return {e["path"]: e["sha256"] for e in m["files"]}

    assert digests(p1) == digests(p2)


def test_pack_reimport_repairs_corrupted_derived_files(ws, analysed, tmp_path):
    pack = create_pack(ws, tmp_path / "x.acetpack")
    ws2 = create_workspace("rep", tmp_path / "w2")
    try:
        import_pack(ws2, pack)
        rel = ws2.db.conn.execute("SELECT output_relpath FROM derived_result ORDER BY output_relpath").fetchone()[0]
        victim = next(p for p in (ws2.path / rel).rglob("*") if p.is_file())
        good = victim.read_bytes()
        victim.write_bytes(b"evil")
        res = import_pack(ws2, pack)
        assert victim.read_bytes() == good
        assert res["derived_repaired"] == 1
        assert [q.read_bytes() for q in (ws2.path / "quarantine" / "corrupted-derived").iterdir()] == [b"evil"]
    finally:
        ws2.close()


def _rewrite(src: Path, dest: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as z:
        items = {n: z.read(n) for n in z.namelist()}
    items = mutate(items)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in items.items():
            z.writestr(n, d)
    return dest


@pytest.mark.acceptance("ACC-023", "ACC-066", "ACC-085")
def test_hostile_packs_are_refused_before_any_write(ws, product_id, tmp_path):
    import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    good = create_pack(ws, tmp_path / "g.acetpack")
    target = create_workspace("t", tmp_path / "wt")
    try:

        def rows() -> int:
            return target.db.conn.execute("SELECT count(*) FROM build").fetchone()[0]

        def tamper(items):
            k = "metadata/build.jsonl"
            items[k] = items[k].replace(b'"status":"', b'"status":"X')
            return items

        def traversal(items):
            items["../../evil.txt"] = b"x"
            return items

        def future(items):
            m = json.loads(items["manifest.json"])
            m["schema_version"] = 99
            items["manifest.json"] = json.dumps(m).encode()
            return items

        cases = {
            "tamper": ("ACET-PACK-001", tamper),
            "traversal": ("ACET-SEC-001", traversal),
            "future": ("ACET-PACK-002", future),
        }
        for name, (code, fn) in cases.items():
            assert name != "tamper" or fn({"metadata/build.jsonl": b'{"status":"A"}'}) != {
                "metadata/build.jsonl": b'{"status":"A"}'
            }
            bad = _rewrite(good, tmp_path / f"{name}.acetpack", fn)
            with pytest.raises(AcetError) as ei:
                import_pack(target, bad)
            assert ei.value.code == code, name
            assert rows() == 0
        bomb = tmp_path / "bomb.acetpack"
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", b"{}")
            z.writestr("checksums.txt", b"")
            z.writestr("results/zero.bin", b"\0" * (20 * 1024 * 1024))
        with pytest.raises(AcetError) as ei:
            import_pack(target, bomb)
        assert ei.value.code == "ACET-SEC-002"
        link = tmp_path / "link.acetpack"
        with zipfile.ZipFile(link, "w") as z:
            info = zipfile.ZipInfo("results/link")
            info.external_attr = 0o120777 << 16
            z.writestr(info, "/etc/passwd")
        with pytest.raises(AcetError) as ei:
            import_pack(target, link, limits=ArchiveLimits())
        assert ei.value.code == "ACET-SEC-001"
        assert not list((target.path / "temp").glob("acetpack-*"))
    finally:
        target.close()


@pytest.mark.acceptance("ACC-032", "ACC-076")
def test_diagnostics_are_sanitized(ws, product_id, tmp_path):
    from acet.analysis.orchestrator import analyze_build

    pdb_name = "C:\\Users\\alice\\src\\guard\\x64\\Release\\guard.pdb"
    res = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    analyze_build(ws, res.build_id, "FAST@1")
    log = next((ws.path / "logs" / "processor_runs").glob("*/stdout.log"))
    log.write_text(f"loading {pdb_name} from {ws.path} for {Path.home()}\n", encoding="utf-8")
    pkg = create_diagnostic_package(ws, tmp_path / "diag.zip")
    with zipfile.ZipFile(pkg) as z:
        blob = "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())
        names = z.namelist()
    assert "alice" not in blob and "guard.pdb" not in blob and str(ws.path) not in blob
    assert "<PDB-PATH>" in blob and "<WORKSPACE>" in blob
    assert not any(n.startswith("artifacts") for n in names)
    shas = [r[0] for r in ws.db.conn.execute("SELECT sha256 FROM artifact")]
    raw = pkg.read_bytes()
    for sha in shas:
        assert ws.store.path_for(sha).read_bytes() not in raw


@pytest.mark.acceptance("ACC-083", "ACC-046")
def test_cleanup_dry_run_then_apply_never_touches_sources(ws, product_id, tmp_path):
    import os

    res = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    junk = ws.path / "temp" / "left.tmp"
    junk.write_bytes(b"x" * 1000)
    old = ws.path / "quarantine" / "orphans" / ("e" * 64)
    old.parent.mkdir(parents=True)
    old.write_bytes(b"y" * 500)
    os.utime(old, (time.time() - 40 * 86400,) * 2)
    plan = plan_cleanup(ws)
    assert {i.category for i in plan.items} == {"temp", "quarantine"}
    assert plan.total_bytes == 1500 and junk.exists()  # dry run changed nothing
    assert apply_cleanup(ws, plan) == 1500
    assert not junk.exists() and not old.exists()
    assert all(ws.store.verify(s) for s in res.new_artifacts)


@pytest.mark.acceptance("ACC-084", "ACC-148", "ACC-036")
def test_purge_keeps_shared_artifacts(ws, product_id, tmp_path):
    a = import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    shared_dir = write_build(
        tmp_path / "b",
        {"Fict.sys": driver(b"other-driver"), "fict_user.dll": (tmp_path / "a" / "fict_user.dll").read_bytes()},
    )
    b = import_build(ws, ImportRequest([shared_dir], product_id))
    with pytest.raises(AcetError):
        plan_purge(ws, a.build_id)  # not in trash
    soft_delete_build(ws, a.build_id)
    plan = plan_purge(ws, a.build_id)
    shared = (set(a.new_artifacts) | set(a.reused_artifacts)) & (set(b.new_artifacts) | set(b.reused_artifacts))
    assert set(plan["kept_shared"]) == shared and len(shared) == 1
    apply_purge(ws, a.build_id)
    for sha in plan["to_quarantine"]:
        assert not ws.store.exists(sha)
        assert (
            ws.db.conn.execute("SELECT integrity_state FROM artifact WHERE sha256=?", (sha,)).fetchone()[0]
            == "QUARANTINED"
        )
    for sha in shared:
        assert ws.store.verify(sha)
    assert reconcile(ws).clean


@pytest.mark.acceptance("ACC-045")
def test_backup_restore_metadata_without_artifact_duplication(ws, product_id, tmp_path):
    import_build(ws, ImportRequest([build_a(tmp_path / "a")], product_id))
    blobs_before = sum(1 for _ in ws.store.iter_blobs())
    bk = backup_metadata(ws)
    assert bk.stat().st_size < 5 * 1024 * 1024
    add_annotation(ws, "product", product_id, "added after backup")
    restored = restore_metadata(ws, bk)
    try:
        assert restored.db.conn.execute("SELECT count(*) FROM annotation").fetchone()[0] == 0
        assert sum(1 for _ in restored.store.iter_blobs()) == blobs_before
        assert restored.db.integrity_check() == []
    finally:
        restored.close()


@pytest.mark.acceptance("ACC-020", "ACC-119")
def test_global_search_finds_all_kinds_quickly(ws, analysed):
    b, _run = analysed
    add_annotation(ws, "build", b[0], "suspicious integrity probe introduced")
    sha = ws.db.conn.execute("SELECT sha256 FROM artifact LIMIT 1").fetchone()[0]
    lin = ws.db.conn.execute("SELECT id FROM lineage LIMIT 1").fetchone()[0]
    kinds = {
        "v1": "build",
        sha[:12]: "artifact",
        "integrity probe": "annotation",
        lin[:13]: "lineage",
        "GuardScan": "function",
    }
    timings = []
    for q, kind in kinds.items():
        t = time.perf_counter()
        hits = search(ws, q)
        timings.append(time.perf_counter() - t)
        assert any(h["kind"] == kind for h in hits), (q, hits[:3])
    assert max(timings) < 0.25  # P95 target on the reference workspace (§106)
    rebuild_indexes(ws)
    aid = search(ws, "integrity probe")[0]["id"]
    delete_annotation(ws, aid)
    assert not [h for h in search(ws, "integrity probe") if h["kind"] == "annotation"]


@pytest.mark.acceptance("ACC-131", "ACC-132")
def test_human_assertions_never_touch_raw_results(ws, analysed):
    _b, run = analysed
    before = [tuple(r) for r in ws.db.conn.execute("SELECT * FROM matcher_result ORDER BY id")]
    cm = ws.db.conn.execute("SELECT id FROM consensus_match WHERE analysis_run_id=? LIMIT 1", (run,)).fetchone()[0]
    add_assertion(ws, "consensus_match", cm, "HUMAN_ASSERTION", reason="manual review: different function")
    assert [tuple(r) for r in ws.db.conn.execute("SELECT * FROM matcher_result ORDER BY id")] == before
    gt = json.loads((DEMO / "ground_truth.json").read_text())
    assert "human" not in json.dumps(gt).lower()  # benchmark labels come only from the dataset file


@pytest.mark.acceptance("ACC-098", "ACC-125")
def test_mode_safety_and_secrets(ws):
    with pytest.raises(AcetError):
        set_setting(ws, "calibration.min_samples", 5)  # scientific: refused in Normal mode
    set_setting(ws, "analysis.default_profile", "FAST@1")
    set_setting(ws, "ui.mode", "RESEARCH")
    set_setting(ws, "calibration.min_samples", 50)
    with pytest.raises(AcetError):
        set_setting(ws, "symbols.remote_provider", "token-abc123")
    dump = "\n".join(ws.db.conn.iterdump())
    assert "token-abc123" not in dump
    if sys.platform != "win32":
        from acet.platform.secrets import store_secret

        with pytest.raises(AcetError):
            store_secret("s3cr3t")


def test_unicode_survives_export(ws, product_id, tmp_path):
    folder = write_build(tmp_path / "u", {"Пилот_驱动.sys": driver(b"uni")})
    import_build(ws, ImportRequest([folder], product_id))
    pack = create_pack(ws, tmp_path / "u.acetpack")
    with zipfile.ZipFile(pack) as z:
        assert "Пилот_驱动.sys" in z.read("metadata/component.jsonl").decode("utf-8")
    assert hashlib.sha256(pack.read_bytes()).hexdigest()
    create_product(ws, "Ünïcödé Prödüct")
    assert search(ws, "Ünïcödé")[0]["kind"] == "product"
