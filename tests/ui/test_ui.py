"""PySide6 UI (P13): navigation, Ctrl+K, keyboard import→analyze→compare, large tables, responsiveness,
error dialogs, accessibility (spec §28–38, §51, §106)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QPushButton, QTableView

from acet.domain.error_codes import AcetError
from acet.ui.app import MainWindow, SearchDialog
from acet.ui.widgets import ErrorDialog, Table
from acet.ui.wizards import ImportWizard

DEMO = Path(__file__).resolve().parents[2] / "datasets" / "demo"


@pytest.fixture
def replay(monkeypatch):
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DEMO / "golden" / "ghidra"))
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON"):
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


def _idle(qtbot, w, timeout=30_000):
    qtbot.waitUntil(lambda: w.runner.active == 0, timeout=timeout)


def test_all_pages_load_without_errors(qtbot, win):
    errors = []
    win.show_error = lambda err, tb: errors.append((err.code, tb))
    for i in range(win.nav.count()):
        win.nav.setCurrentRow(i)
        _idle(qtbot, win)
    assert not errors, errors
    assert win.health.text().startswith("Health:")


@pytest.mark.acceptance("ACC-044")
def test_keyboard_navigation_shortcuts(qtbot, win):
    from PySide6.QtTest import QTest

    win.activateWindow()
    QTest.keyClick(win, Qt.Key.Key_4, Qt.KeyboardModifier.AltModifier)
    assert win.stack.currentWidget().title == "Compare"
    QTest.keyClick(win, Qt.Key.Key_1, Qt.KeyboardModifier.AltModifier)
    assert win.stack.currentWidget().title == "Dashboard"
    _idle(qtbot, win)


@pytest.mark.acceptance("ACC-044", "ACC-042")
def test_import_analyze_compare_by_keyboard(qtbot, win, replay):
    for v in (1, 2):
        wiz = ImportWizard(win.ctx)
        qtbot.addWidget(wiz)
        wiz.show()
        _idle(qtbot, win)
        wiz.path.setText(str(DEMO / "builds" / f"v{v}"))
        wiz.release.setText(f"v{v}")
        wiz.observed.setText(f"2026-0{v}-01")
        for _ in range(3):
            wiz.next()
            _idle(qtbot, win)
        assert wiz.files.model.rowCount() == 2  # detection shown before anything is written
        wiz.next()  # action page (default: Import + FAST)
        wiz.next()  # summary → import runs in background
        qtbot.waitUntil(lambda wiz=wiz: wiz.result is not None, timeout=60_000)
        _idle(qtbot, win, 120_000)
        assert wiz.result.created_build
    win.goto("Compare")
    _idle(qtbot, win)
    page = win.ctx.pages["Compare"]
    assert page.left.count() == 2
    page.left.setCurrentIndex(0)
    page.right.setCurrentIndex(1)
    page.compare()
    _idle(qtbot, win, 180_000)
    page.refresh()
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: page.functions.model.rowCount() > 0, timeout=30_000)
    page.functions.view.selectRow(0)
    _idle(qtbot, win)
    assert "supporting_evidence" in page.inspector.toPlainText()
    page.decision.setCurrentText("EXACT")
    assert 0 < page.functions.proxy.rowCount() <= page.functions.model.rowCount()


@pytest.mark.acceptance("ACC-020")
def test_ctrl_k_search(qtbot, win):
    from acet.application.workspace import open_workspace
    from acet.ingest.importer import ImportRequest, import_build

    ws = open_workspace(win.ws_path)
    try:
        pid = ws.db.conn.execute("SELECT id FROM product").fetchone()[0]
        import_build(ws, ImportRequest([DEMO / "builds" / "v1"], pid, release_label="release-77"))
    finally:
        ws.close()
    dlg = SearchDialog(win)
    qtbot.addWidget(dlg)
    dlg.q.setText("release-77")
    qtbot.waitUntil(lambda: dlg.results.count() > 0, timeout=10_000)
    assert "[build]" in dlg.results.item(0).text()
    dlg.open_first()
    _idle(qtbot, win)
    assert win.stack.currentWidget().title == "Builds"


@pytest.mark.acceptance("ACC-030")
def test_ten_thousand_function_table_stays_interactive(qtbot):
    t = Table([("name", "Name"), ("decision", "Decision"), ("score", "Score")], "Big table")
    qtbot.addWidget(t)
    rows = [
        {"name": f"FUN_{i:08x}", "decision": ("EXACT", "STRONG", "UNRESOLVED")[i % 3], "score": i / 10000}
        for i in range(10_000)
    ]
    t0 = time.perf_counter()
    t.set_rows(rows)
    t.show()
    t.filter.setText("FUN_00000ff")
    t.proxy.sort(2, Qt.SortOrder.DescendingOrder)
    t.proxy.set_column_equals(1, "EXACT")
    elapsed = time.perf_counter() - t0
    assert t.proxy.rowCount() > 0 and elapsed < 1.0


@pytest.mark.acceptance("ACC-029", "ACC-118")
def test_ui_thread_never_blocked_by_heavy_work(qtbot, win):
    gaps: list[float] = []
    last = [time.perf_counter()]

    def tick() -> None:
        now = time.perf_counter()
        gaps.append(now - last[0])
        last[0] = now

    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(tick)
    timer.start()
    done = []
    win.ctx.run(lambda: (time.sleep(1.5), done.append(1)), no_ws=True)
    qtbot.waitUntil(lambda: bool(done), timeout=10_000)
    timer.stop()
    assert len(gaps) > 30 and max(gaps[1:]) < 0.25  # event loop kept turning during 1.5 s of work


def test_error_dialog_shows_actionable_information(qtbot):
    dlg = ErrorDialog(AcetError("ACET-STO-002", "2 artifacts"), "Traceback ...", on_diagnostics=lambda: None)
    qtbot.addWidget(dlg)
    from PySide6.QtWidgets import QLabel

    joined = " ".join(w.text() for w in dlg.findChildren(QLabel))
    assert "ACET-STO-002" in joined and "Impact" in joined and "Recommended action" in joined
    assert not dlg.dev.isVisible() and dlg.dev.toPlainText().startswith("Traceback")


@pytest.mark.acceptance("ACC-044")
def test_accessible_names_everywhere(qtbot, win):
    missing = []
    for w in win.findChildren(QPushButton) + win.findChildren(QTableView):
        if not w.accessibleName() and not w.text() if isinstance(w, QPushButton) else not w.accessibleName():
            missing.append(w)
    assert not missing


@pytest.mark.acceptance("ACC-002")
def test_first_run_wizard_creates_workspace_scans_and_self_tests(qtbot, win, tmp_path):
    from acet.ui.wizards import FirstRunWizard

    wiz = FirstRunWizard(win.ctx)
    qtbot.addWidget(wiz)
    wiz.show()
    wiz.location.setText(str(tmp_path / "first"))
    for _ in range(4):
        wiz.next()
        _idle(qtbot, win, 120_000)
    assert wiz.created is not None and (wiz.created / "acet.db").is_file()
    assert wiz.scan.model.rowCount() > 3  # engines diagnosed
    assert "available" in wiz.engines.text()
    qtbot.waitUntil(lambda: '"ok": true' in wiz.test.toPlainText(), timeout=120_000)


@pytest.mark.acceptance("ACC-009")
@pytest.mark.skipif(__import__("sys").platform != "linux", reason="process discovery via /proc")
def test_killing_engine_worker_does_not_kill_ui(qtbot, win, tmp_path):
    import os
    import signal

    from acet.application.workspace import open_workspace
    from acet.ingest.importer import ImportRequest, import_build
    from tests.fixtures import driver, write_build

    big = write_build(tmp_path / "big", {"big.sys": driver(os.urandom(64 * 1024 * 1024))})
    ws = open_workspace(win.ws_path)
    try:
        pid = ws.db.conn.execute("SELECT id FROM product").fetchone()[0]
        bid = import_build(ws, ImportRequest([big], pid)).build_id
    finally:
        ws.close()
    from acet.analysis.orchestrator import analyze_build

    results = []
    win.ctx.run(analyze_build, bid, "FAST@1", read_only=False, done=results.append)

    def workers() -> list[int]:
        out = []
        for d in os.listdir("/proc"):
            if d.isdigit():
                try:
                    with open(f"/proc/{d}/cmdline", "rb") as fh:
                        if b"acet.engines.worker" in fh.read():
                            out.append(int(d))
                except OSError:
                    pass
        return out

    qtbot.waitUntil(lambda: bool(workers()), timeout=30_000)
    killed = 0
    deadline = time.time() + 60
    while not results and time.time() < deadline:
        for p in workers():
            os.kill(p, signal.SIGKILL)  # simulate an engine crash
            killed += 1
        qtbot.wait(50)
    _idle(qtbot, win, 120_000)
    assert killed >= 1
    assert results and results[0].status in ("COMPLETED_PARTIAL", "FAILED")  # explicit state, not a hang
    assert win.isVisible()
    win.nav.setCurrentRow(9)  # UI still responds
    _idle(qtbot, win)
    assert win.stack.currentWidget().title == "Jobs"
