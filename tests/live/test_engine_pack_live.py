"""Live Engine Pack acceptance on a machine like the one of REAL-TEST-002 (no system Java, Ghidra or Ghidriff).

Runs only with ACET_LIVE_ENGINE_PACK=1 (the engine-pack workflow on a Windows runner): it downloads the real pack
of this build's distribution channel, installs it through the Engines UI and from file, runs the real
``doctor --full`` and a real STANDARD analysis. Nothing here is a fake: no mock, no stub, no local key.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.real_distribution,
    pytest.mark.skipif(os.environ.get("ACET_LIVE_ENGINE_PACK") != "1", reason="live Engine Pack run only"),
]

DEMO = Path(__file__).resolve().parents[2] / "datasets" / "demo"
TMP = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
EVIDENCE = TMP / "acet-live-evidence"
HOME_UI = TMP / "acet-live-home"  # kept after the run: the workflow prints doctor --full from it
HOME_FILE = TMP / "acet-live-home-file"


def _no_system_engines() -> None:
    """The environment observed in REAL-TEST-002."""
    assert shutil.which("java") is None, shutil.which("java")
    assert not os.environ.get("JAVA_HOME") and not os.environ.get("GHIDRA_INSTALL_DIR")
    assert not os.environ.get("ACET_GHIDRA_DIR") and not os.environ.get("ACET_GHIDRIFF_PYTHON")
    assert importlib.util.find_spec("ghidriff") is None and importlib.util.find_spec("pyghidra") is None


def _record(name: str, data: object) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    text = data if isinstance(data, str) else json.dumps(data, indent=2, default=str)
    (EVIDENCE / name).write_text(text, encoding="utf-8")
    print(f"--- {name}\n{text}")


def _doctor(home: Path, name: str) -> dict:
    env = {**os.environ, "ACET_HOME": str(home)}
    out = subprocess.run([sys.executable, "-m", "acet", "doctor", "--full", "--json"], env=env,
                         capture_output=True, text=True, timeout=3600)  # fmt: skip
    text = subprocess.run([sys.executable, "-m", "acet", "doctor", "--full"], env=env,
                          capture_output=True, text=True, timeout=3600).stdout  # fmt: skip
    _record(f"{name}-doctor-full.txt", text)
    assert out.returncode in (0, 10), out.stderr
    return json.loads(out.stdout)


def _assert_live_ready(home: Path, name: str) -> None:
    from acet.platform import engine_manager as em

    st = em.status()
    _record(f"{name}-status.json", st)
    assert st["state"] == "READY", st["state"]
    assert st["profiles"]["FAST"]["state"] == "READY" and st["profiles"]["STANDARD"]["state"] == "READY"
    comps = {c["id"]: c for c in st["components"]}
    for cid in ("java", "ghidra", "ghidriff"):
        assert comps[cid]["state"] == "READY", comps[cid]
    for cid in ("binexport", "bindiff", "qbindiff", "diaphora"):  # never block STANDARD
        assert comps[cid]["role"] in ("OPTIONAL", "EXTERNAL")
    doc = _doctor(home, name)
    checks = {c["name"]: c for c in doc["checks"]}
    st_ = checks["golden self-test"]["data"]["self_test"]
    assert st_["verdict"] == "VERIFIED" and st_["engine_mode"] == "live", st_
    assert "(engine-pack)" in checks["java"]["detail"], checks["java"]
    act = em.active_pack()
    props = (Path(act["path"]) / "ghidra" / "support" / "launch.properties").read_text(encoding="utf-8")
    assert "JAVA_HOME_OVERRIDE=" + (Path(act["path"]) / "runtime" / "java").resolve().as_posix() in props
    assert em.verify_active()["state"] == "VERIFIED"  # running the engines left the pack untouched


def test_install_engine_pack_button_then_live_standard(qtbot, ws, product_id, monkeypatch):
    from acet.analysis.orchestrator import compare_builds
    from acet.ingest.importer import ImportRequest, import_build
    from acet.platform import engine_manager as em
    from acet.ui.app import MainWindow

    _no_system_engines()
    shutil.rmtree(HOME_UI, ignore_errors=True)
    monkeypatch.setenv("ACET_HOME", str(HOME_UI))
    monkeypatch.setenv("ACET_NO_ENGINE_GUIDE", "1")
    before = em.status()
    assert before["state"] in ("NOT_INSTALLED", "DEGRADED") and before["profiles"]["STANDARD"]["state"] == "UNAVAILABLE"
    path = ws.path
    ws.close()
    win = MainWindow(path)
    qtbot.addWidget(win)
    win.show()
    qtbot.waitUntil(lambda: win.runner.active == 0, timeout=60_000)
    assert "Engines:" in win.engines_button.text() and "READY" not in win.engines_button.text()
    win.engines_button.click()  # the top-bar button opens the Engine Manager
    mgr = win.engine_dialog.manager
    qtbot.waitUntil(lambda: win.runner.active == 0, timeout=60_000)
    consent: dict = {}

    def accept(dlg) -> bool:  # the consent dialog is shown with the signed index entry; the user confirms
        consent["entry"] = dlg.entry
        return True

    mgr.ask = accept
    mgr.install_btn.click()  # "Install Engine Pack"
    qtbot.waitUntil(lambda: "entry" in consent, timeout=120_000)
    entry = consent["entry"]
    _record("consent-entry.json", entry)
    assert entry["archive_url"].startswith("https://") and entry["platform"] == "win-x64"
    assert {c["id"] for c in entry["components"]} >= {"java", "ghidra", "ghidriff"}
    qtbot.waitUntil(lambda: not mgr.busy and win.runner.active == 0, timeout=45 * 60_000)
    assert mgr.step.text().startswith("READY"), (mgr.step.text(), mgr.error.text())
    assert "READY" in win.engines_button.text()
    _record("install-log.txt", em.log_path().read_text(encoding="utf-8"))
    _assert_live_ready(HOME_UI, "ui-install")
    # STANDARD really runs on the pack's engines (no system Java/Ghidra/Ghidriff).
    from acet.application.workspace import open_workspace

    w = open_workspace(path)
    try:
        b1 = import_build(w, ImportRequest([DEMO / "builds" / "v1"], product_id)).build_id
        b2 = import_build(w, ImportRequest([DEMO / "builds" / "v2"], product_id)).build_id
        s = compare_builds(w, b1, b2, "STANDARD@1")
        _record("standard-run.json", s.to_dict())
        assert s.status == "COMPLETED", s.to_dict()
        pack = w.db.conn.execute(
            "SELECT ep.name FROM analysis_run ar JOIN engine_pack ep ON ep.id=ar.engine_pack_id WHERE ar.id=?",
            (s.run_id,),
        ).fetchone()
        engines = [r[0] for r in w.db.conn.execute(
            "SELECT DISTINCT engine || ' ' || engine_version FROM matcher_result WHERE analysis_run_id=?", (s.run_id,)
        )]  # fmt: skip
        _record("standard-engines.json", {"engine_pack": pack[0] if pack else None, "matchers": engines})
        assert pack is not None and pack[0].startswith("acet-engines-win64")
        assert any("ghidriff" in e for e in engines), engines
        # live Ghidra extraction agrees with the recorded golden extraction (as ACC-038)
        for rel, sha in w.db.conn.execute(
            "SELECT dr.output_relpath, di.input_ref FROM derived_result dr JOIN derived_input di ON"
            " di.derived_result_id=dr.id WHERE dr.processor_id='ghidra.extract'"
        ):
            live = json.loads((w.path / rel / "result.json").read_text(encoding="utf-8"))
            golden = json.loads((DEMO / "golden" / "ghidra" / f"{sha}.json").read_text(encoding="utf-8"))
            assert live.get("engine_mode", "live") != "replay"
            assert [(f["entry"], f["insns"]) for f in live["functions"]] == [
                (f["entry"], f["insns"]) for f in golden["functions"]
            ]
    finally:
        w.close()
    win.runner.wait(30_000)


def test_install_from_file_same_real_pack(monkeypatch):
    from acet.platform import engine_manager as em

    _no_system_engines()
    downloaded = sorted((HOME_UI / "engines" / "downloads").glob("*.acetengine"))
    assert downloaded, "run after the Install Engine Pack test: it downloaded the real pack"
    archive = TMP / downloaded[0].name.split("-", 1)[1]
    shutil.copyfile(downloaded[0], archive)
    shutil.rmtree(HOME_FILE, ignore_errors=True)
    monkeypatch.setenv("ACET_HOME", str(HOME_FILE))
    assert em.status()["profiles"]["STANDARD"]["state"] == "UNAVAILABLE"
    res = em.install_archive(archive)  # "Install from file…": the same verify/extract/health/activate path
    assert res.state == "READY", res
    _record("file-install.json", {"steps": res.steps, "pack": res.pack, "verdict": res.verification["verdict"]})
    _assert_live_ready(HOME_FILE, "file-install")
