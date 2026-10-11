"""Watch page: add a folder, detect new versions, compare the last two, automatic checks, detection dialog."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import Qt

from acet.application import watch
from acet.ui.app import MainWindow

DEMO = Path(__file__).resolve().parents[2] / "datasets" / "demo" / "builds"


@pytest.fixture
def win(qtbot, ws):
    path = ws.path
    ws.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    w.show()
    yield w
    w.runner.wait(30_000)


def _idle(qtbot, w, timeout=60_000):
    qtbot.waitUntil(lambda: w.runner.active == 0, timeout=timeout)


def _install(dest: Path, version: str) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(DEMO / version, dest)


def test_watch_page_captures_versions_and_opens_the_comparison(qtbot, win, tmp_path):
    folder = tmp_path / "Common Files" / "Guard"
    _install(folder, "v1")
    _idle(qtbot, win)
    win.goto("Watch")
    page = win.ctx.pages["Watch"]
    page.add_folder(str(folder), "Guard")
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: page.sources.model.rowCount() == 1, timeout=10_000)
    page.sources.view.selectRow(0)
    page.scan_now()
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: "NEW VERSION" in page.sources.model.rows[0]["status_text"], timeout=30_000)
    assert page.sources.model.rows[0]["versions"] == 1 and "NEW VERSION of" in page.state.text()
    page.scan_now()
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: "unchanged" in page.sources.model.rows[0]["status_text"], timeout=30_000)
    _install(folder, "v2")  # the product updated itself
    page.scan_now()
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: page.sources.model.rows[0]["versions"] == 2, timeout=30_000)
    page.sources.view.selectRow(0)
    page.show_history()
    assert page.history.model.rowCount() == 2 and page.history.model.rows[0]["kind"] == "new build"
    page.compare_last()
    _idle(qtbot, win)
    compare = win.ctx.pages["Compare"]
    pair = watch.last_two_builds(page.selected())
    qtbot.waitUntil(lambda: (compare.left.currentData(), compare.right.currentData()) == pair, timeout=10_000)
    assert win.stack.currentWidget().title == "Compare"


def test_automatic_checks_are_scheduled_and_remembered(qtbot, win):
    _idle(qtbot, win)
    win.goto("Watch")
    page = win.ctx.pages["Watch"]
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: page.loaded, timeout=10_000)
    assert page.auto.isChecked() and page.timer.isActive() and page.timer.interval() == 30 * 60_000  # default
    page.auto.setChecked(False)
    assert not page.timer.isActive()
    page.interval.setValue(15)
    page.auto.setChecked(True)
    qtbot.waitUntil(lambda: not page.save_timer.isActive(), timeout=5_000)
    _idle(qtbot, win)
    assert page.timer.isActive() and page.timer.interval() == 15 * 60_000
    from acet.application.workspace import open_workspace

    w = open_workspace(win.ws_path, read_only=True)
    state = watch.load_state(w)
    w.close()
    assert state["auto"] is True and state["interval_minutes"] == 15  # the final values were written
    w2 = MainWindow(win.ws_path)  # ACET restarted: the schedule is restored without opening the page
    qtbot.addWidget(w2)
    _idle(qtbot, w2)
    p2 = w2.ctx.pages["Watch"]
    qtbot.waitUntil(lambda: p2.loaded, timeout=10_000)
    assert p2.auto.isChecked() and p2.timer.isActive() and p2.timer.interval() == 15 * 60_000
    w2.runner.wait(30_000)


def test_manual_detect_adds_only_what_the_user_ticks(qtbot, ws, tmp_path, monkeypatch):
    """With automatic discovery switched off, Detect… proposes and adds only the ticked locations."""
    watch.set_option(ws, "auto_discover", False)
    path = ws.path
    ws.close()
    win = MainWindow(path)
    qtbot.addWidget(win)
    win.show()
    a, b = tmp_path / "BattlEye", tmp_path / "Game" / "EasyAntiCheat"
    _install(a, "v1")
    _install(b, "v2")
    cands = [{"product": "BattlEye", "label": "BattlEye (system)", "paths": [str(a)]},
             {"product": "EasyAntiCheat", "label": "Game — EasyAntiCheat", "paths": [str(b)]}]  # fmt: skip
    monkeypatch.setattr(watch, "detect_candidates", lambda: cands)
    _idle(qtbot, win)
    win.goto("Watch")
    page = win.ctx.pages["Watch"]

    def tick_first(dlg):  # type: ignore[no-untyped-def]
        assert dlg.list.count() == 2 and dlg.chosen() == []  # nothing pre-selected
        dlg.list.item(0).setCheckState(Qt.CheckState.Checked)
        return True

    page.ask_detect = tick_first
    page.detect()
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: page.sources.model.rowCount() == 1, timeout=10_000)
    assert page.sources.model.rows[0]["product"] == "BattlEye"
    win.runner.wait(30_000)


def test_fully_automatic_without_any_click(qtbot, ws, tmp_path, monkeypatch):
    pf = tmp_path / "pf"
    folder = pf / "Common Files" / "BattlEye"
    _install(folder, "v1")
    monkeypatch.setenv("ProgramFiles(x86)", str(pf))
    path = ws.path
    ws.close()
    w = MainWindow(path)  # ACET is simply opened
    qtbot.addWidget(w)
    w.show()
    page = w.ctx.pages["Watch"]
    qtbot.waitUntil(lambda: page.sources.model.rowCount() == 1, timeout=60_000)
    qtbot.waitUntil(lambda: page.sources.model.rows[0]["versions"] == 1, timeout=60_000)
    assert page.sources.model.rows[0]["product"] == "BattlEye" and page.timer.isActive()
    archive = Path(page.archive.text())
    assert (archive / "BattlEye").is_dir() and len(list((archive / "BattlEye").iterdir())) == 1
    _install(folder, "v2")  # the anti-cheat updates itself
    page.auto_scan()  # what the timer does every N minutes
    qtbot.waitUntil(lambda: page.sources.model.rows[0]["versions"] == 2, timeout=60_000)
    _idle(qtbot, w)
    assert len(list((archive / "BattlEye").iterdir())) == 2
    assert "NEW VERSION of BattlEye" in page.state.text()
    assert "Engine Pack" in page.state.text()  # no engines in this test: the comparison says what it needs
    w.runner.wait(30_000)


def test_older_versions_from_steam_are_downloaded_imported_and_listed(qtbot, win, tmp_path, monkeypatch):
    """The whole Steam flow from the window: game and depot found, SteamDB list pasted, version ticked, command
    handed to the Steam console (simulated: Steam writes the files and its log line), import without a click."""
    from acet.application import steam_history as sh
    from tests.integration.test_steam_history import APP, DEPOT, _steam, _steam_downloads

    root = _steam(tmp_path)
    monkeypatch.setenv("ACET_STEAM_ROOT", str(root))
    _idle(qtbot, win)
    win.goto("Watch")
    page = win.ctx.pages["Watch"]
    page.older_versions()
    dlg = page.steam_dialog
    dlg.timer.setInterval(100)
    _idle(qtbot, win)
    qtbot.waitUntil(lambda: dlg.game.count() == 1, timeout=10_000)
    assert "Some One" in dlg.account.text()
    assert dlg.depot.currentData()["depot"] == DEPOT
    old = "5743210987654321098"
    opened: list[str] = []

    def steam_console() -> None:  # what the user does in Steam: Ctrl+V, Enter; Steam then downloads
        from PySide6.QtGui import QGuiApplication

        opened.append(QGuiApplication.clipboard().text())
        QTimer.singleShot(200, lambda: _steam_downloads(root, old, "v1"))

    from PySide6.QtCore import QTimer

    dlg.open_console = steam_console
    dlg.paste.setPlainText(f"12 August 2026 – 09:05:00 UTC\t2 months ago\t{old}\n")
    assert dlg.versions.count() == 1
    dlg.versions.item(0).setCheckState(Qt.CheckState.Checked)
    dlg.start.click()
    qtbot.waitUntil(lambda: bool(opened), timeout=10_000)
    assert opened == [f"download_depot {APP} {DEPOT} {old}"]
    qtbot.waitUntil(lambda: "Imported Some Game 2026-08-12" in dlg.state.text(), timeout=60_000)
    _idle(qtbot, win)
    assert dlg.start.isEnabled() and not dlg.stop.isEnabled()
    assert "already imported" in dlg.versions.item(0).text()
    assert not sh.depot_dir(root, APP, DEPOT).exists()
