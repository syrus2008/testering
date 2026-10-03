"""Engine Pack Manager UI (ACC-ENGINE-005/006): Engines button, first-run guide, install with progress, cancel,
offline error + install from file, responsiveness, profile gating, Settings → Analysis Engines."""

from __future__ import annotations

import itertools
import os
import time
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QSettings, QTimer

from acet.platform import ed25519, signing
from acet.platform import engine_manager as em
from acet.ui import engines as ui_engines
from acet.ui.app import MainWindow
from acet.ui.engines import FAST_ONLY_KEY, EngineManagerWidget, EngineWelcomeDialog
from tests.integration.test_engine_manager import SECRET, VERIFIED, make_pack


@pytest.fixture(autouse=True)
def pack_env(monkeypatch):
    key = {
        "key_id": "rel",
        "alg": "ed25519",
        "public_key": ed25519.public_key(SECRET).hex(),
        "purposes": ["engine-pack"],
    }
    monkeypatch.setattr(signing, "_bundled_store", lambda: {"keys": [key]})
    monkeypatch.setattr(em, "doctor_health_check", lambda d, m: VERIFIED)  # engines here are structural fakes
    monkeypatch.setattr(em.shutil, "which", lambda name: None)  # a clean machine: no system Java
    monkeypatch.delenv("ACET_NO_ENGINE_GUIDE", raising=False)  # the first-run guide is under test here
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_GHIDRA_REPLAY_DIR", "ACET_GHIDRIFF_PYTHON", "JAVA_HOME"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def win(qtbot, ws, product_id):
    path = ws.path
    ws.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    w.show()
    yield w
    w.runner.wait(30_000)


def _idle(qtbot, w, timeout=60_000):
    qtbot.waitUntil(lambda: w.runner.active == 0, timeout=timeout)


@pytest.mark.acceptance("ACC-ENGINE-005")
def test_engines_button_and_first_run_guide(qtbot, win):
    _idle(qtbot, win)
    btn = win.engines_button
    assert btn.isVisible() and btn.text().startswith("Engines: ")
    assert "⚠" in btn.text() and ("DEGRADED" in btn.text() or "NOT INSTALLED" in btn.text())  # symbol + word
    assert "status" in btn.accessibleDescription().lower()
    guide = win.engine_welcome
    assert isinstance(guide, EngineWelcomeDialog) and guide.isVisible()
    assert "FAST analysis" in guide.findChildren(type(win.ws_label))[0].text()
    guide.choose("fast")  # Continue with FAST only: no nagging next time
    assert QSettings("ACET", "ACET").value(FAST_ONLY_KEY) in (True, "true")
    w2 = MainWindow(win.ws_path)
    qtbot.addWidget(w2)
    _idle(qtbot, w2)
    assert not hasattr(w2, "engine_welcome")
    assert "Engines:" in w2.engines_button.text()  # still visible, still DEGRADED
    w2.runner.wait(30_000)


@pytest.mark.acceptance("ACC-ENGINE-005", "ACC-ENGINE-006")
def test_install_from_file_with_progress_and_ready_profiles(qtbot, win, tmp_path):
    _idle(qtbot, win)
    win.open_engines()
    dlg = win.engine_dialog
    mgr: EngineManagerWidget = dlg.manager
    _idle(qtbot, win)
    profiles = {r["profile"]: r["state_text"] for r in mgr.profiles.model.rows}
    assert profiles["FAST"].endswith("READY") and profiles["STANDARD"].endswith("UNAVAILABLE")
    archive = make_pack(tmp_path, extra={f"ghidra/lib{i}.jar": os.urandom(400_000) for i in range(60)})
    ticks: list[float] = []
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.append(time.monotonic()))
    timer.start(20)
    steps: list[str] = []
    mgr.bridge.progress.connect(lambda s, d, t, m: steps.append(s))
    mgr.install_from_file(str(archive))
    assert mgr.cancel_btn.isEnabled() and not mgr.install_btn.isEnabled()
    _idle(qtbot, win)
    timer.stop()
    gaps = [b - a for a, b in itertools.pairwise(ticks)]
    assert len(ticks) > 5 and max(gaps) < 0.25, (len(ticks), max(gaps))  # the event loop never stalled
    assert {"verify", "extract", "health"} <= set(steps)
    assert em.active_pack()["version"] == "1.0.0"
    comps = {r["id"]: r["state_text"] for r in mgr.components.model.rows}
    assert comps["java"].endswith("READY") and comps["ghidra"].endswith("READY")
    assert comps["diaphora"].endswith("NOT_CONFIGURED") or "NOT CONFIGURED" in comps["diaphora"]
    assert "acet-engines 1.0.0" in mgr.summary.text()
    # STANDARD becomes available (DEGRADED: Ghidriff not in this pack), never READY without its engines.
    profiles = {r["profile"]: r["state_text"] for r in mgr.profiles.model.rows}
    assert profiles["STANDARD"].endswith("DEGRADED")
    assert "DEGRADED" in win.engines_button.text()


def test_cancel_and_offline_error_then_retry_from_file(qtbot, win, tmp_path, monkeypatch):
    _idle(qtbot, win)
    win.open_engines()
    mgr = win.engine_dialog.manager
    _idle(qtbot, win)
    monkeypatch.setenv("ACET_ENGINE_INDEX_URL", "http://127.0.0.1:9/index.json")
    mgr.install()
    _idle(qtbot, win)
    assert "NETWORK_UNAVAILABLE" in mgr.step.text() and "Install from file" in mgr.step.text()
    assert "OFFLINE" in win.engines_button.text()
    assert "ACET-EPM-001" in mgr.error.text()
    # Cancel during extraction keeps the previous state.
    big = make_pack(tmp_path, "1.0.0", extra={f"ghidra/blob{i}.bin": os.urandom(200_000) for i in range(40)})
    mgr.bridge.progress.connect(lambda s, d, t, m: mgr.cancel() if s == "extract" else None)
    mgr.install_from_file(str(big))
    _idle(qtbot, win)
    assert mgr.step.text().startswith("CANCELLED") and em.active_pack() is None
    mgr.bridge.progress.disconnect()
    mgr.bridge.progress.connect(mgr._on_progress)
    mgr.install_from_file(str(big))  # retry
    _idle(qtbot, win)
    assert em.active_pack()["version"] == "1.0.0"
    assert "OFFLINE" not in win.engines_button.text()


@pytest.mark.acceptance("ACC-ENGINE-006")
def test_standard_without_engines_offers_install_or_fast(qtbot, win, monkeypatch):
    from tests.fixtures import build_a, build_b

    _idle(qtbot, win)
    page = win.ctx.pages["Compare"]
    from acet.application.workspace import open_workspace
    from acet.ingest.importer import ImportRequest, import_build

    ws = open_workspace(win.ws_path)
    pid = ws.db.conn.execute("SELECT id FROM product").fetchone()[0]
    tmp = Path(win.ws_path).parent
    b1 = import_build(ws, ImportRequest([build_a(tmp / "a")], pid)).build_id
    b2 = import_build(ws, ImportRequest([build_b(tmp / "b")], pid)).build_id
    ws.close()
    win.goto("Compare")
    _idle(qtbot, win)
    page.left.setCurrentIndex(page.left.findData(b1))
    page.right.setCurrentIndex(page.right.findData(b2))
    page.profile.setCurrentText("STANDARD@1")
    seen: dict[str, object] = {}

    def choose_fast(box):  # type: ignore[no-untyped-def]
        seen["text"] = box.text()
        seen["buttons"] = [b.text() for b in box.buttons()]
        box.buttons()[[b.text() for b in box.buttons()].index("Use FAST instead")].click()

    monkeypatch.setattr(ui_engines, "MODAL_EXEC", choose_fast)
    page.compare()
    _idle(qtbot, win)
    assert "STANDARD analysis requires the ACET Engine Pack" in seen["text"]
    assert {"Install Engine Pack", "Use FAST instead"} <= set(seen["buttons"])
    from acet.application.workspace import open_workspace as ow

    ws = ow(win.ws_path)
    runs = ws.db.conn.execute("SELECT resolved_config_json FROM analysis_run WHERE scope_type='compare'").fetchall()
    ws.close()
    assert runs and all('"FAST"' in r[0] for r in runs)  # ran as FAST, nothing failed


def test_settings_embeds_the_same_manager(qtbot, win):
    win.goto("Settings")
    _idle(qtbot, win)
    s = win.ctx.pages["Settings"]
    assert isinstance(s.engines, EngineManagerWidget)
    assert s.engines.components.model.rows and "Install location" in s.engines.summary.text()


@pytest.mark.acceptance("ACC-ENGINE-005")
def test_component_status_and_reasons_are_never_truncated(qtbot, win):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QHeaderView

    _idle(qtbot, win)
    win.open_engines()
    dlg = win.engine_dialog
    mgr: EngineManagerWidget = dlg.manager
    _idle(qtbot, win)
    view = mgr.components.view
    header = view.horizontalHeader()
    keys = [k for k, _ in mgr.components.model.columns]
    status_col, why_col = keys.index("state_text"), keys.index("why")
    fm = view.fontMetrics()
    widest = max(fm.horizontalAdvance(t) for t in mgr.components.model.display_column(status_col))
    assert "NOT CONFIGURED" in " ".join(mgr.components.model.display_column(status_col))
    assert header.sectionSize(status_col) >= widest  # the status word is shown whole, never "NOT ..."
    assert header.sectionResizeMode(why_col) == QHeaderView.ResizeMode.Stretch and view.wordWrap()
    first_why = mgr.components.model.index(0, why_col)
    assert mgr.components.model.data(first_why, Qt.ItemDataRole.ToolTipRole) == mgr.components.model.data(first_why)
    # the wrapped explanation is fully visible: its row is as tall as the wrapped text needs

    def fits() -> bool:  # every row as tall as Qt's own delegate says its wrapped text needs
        return all(view.rowHeight(r) >= view.sizeHintForRow(r) for r in range(mgr.components.model.rowCount()))

    before = view.sizeHintForRow(0)
    dlg.resize(dlg.width() - 250, dlg.height())  # narrower window: the explanation wraps on more lines
    qtbot.wait(200)
    rows = [(view.rowHeight(r), view.sizeHintForRow(r)) for r in range(mgr.components.model.rowCount())]
    assert view.sizeHintForRow(0) > before, (before, rows, header.sectionSize(why_col))  # it does wrap more
    qtbot.waitUntil(fits, timeout=3000)
    profiles = mgr.profiles.view.horizontalHeader()
    assert profiles.sectionResizeMode(2) == QHeaderView.ResizeMode.Stretch
