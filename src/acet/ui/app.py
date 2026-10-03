"""Main window (spec §28): navigation, Ctrl+K global search, health/jobs status bar, error dialogs."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

import acet
from acet.domain.error_codes import AcetError
from acet.ui.pages import PAGES, Page
from acet.ui.tasks import TaskRunner
from acet.ui.widgets import ErrorDialog


class SearchDialog(QDialog):
    """Ctrl+K: builds, artifact hashes, functions, lineages, annotations (ACC-020)."""

    def __init__(self, win: MainWindow) -> None:
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Search (Ctrl+K)")
        self.resize(640, 400)
        lay = QVBoxLayout(self)
        self.q = QLineEdit()
        self.q.setPlaceholderText("Build, release, SHA-256 prefix, function, lineage, annotation…")
        self.q.setAccessibleName("Search query")
        self.results = QListWidget()
        self.results.setAccessibleName("Search results")
        lay.addWidget(self.q)
        lay.addWidget(self.results)
        self.q.textChanged.connect(self.search)
        self.q.returnPressed.connect(self.open_first)
        self.results.itemActivated.connect(self.open_item)

    def search(self, text: str) -> None:
        from acet.application.search import search

        if len(text.strip()) < 2:
            self.results.clear()
            return

        def show(hits: list[dict[str, Any]]) -> None:
            if self.q.text() != text:
                return  # stale result
            self.results.clear()
            for h in hits:
                it = QListWidgetItem(f"[{h['kind']}] {h['title']}  {h.get('detail') or ''}")
                it.setData(Qt.ItemDataRole.UserRole, h)
                self.results.addItem(it)

        self.win.ctx.run(search, text, done=show)

    def open_first(self) -> None:
        if self.results.count():
            self.open_item(self.results.item(0))

    def open_item(self, item: QListWidgetItem) -> None:
        h = item.data(Qt.ItemDataRole.UserRole)
        kind = h["kind"]
        if kind == "build":
            self.win.ctx.open_build(h["id"])
        elif kind in ("function", "lineage"):
            self.win.ctx.goto("Lineage")
        elif kind == "product":
            self.win.ctx.goto("Products")
        elif kind == "artifact":
            self.win.ctx.goto("Builds")
        else:
            self.win.ctx.goto("Dashboard")
        self.accept()


class Context:
    """What pages need from the shell (keeps pages decoupled from MainWindow)."""

    def __init__(self, win: MainWindow) -> None:
        self.win = win
        self.pages: dict[str, Page] = {}

    def run(
        self,
        fn: Callable[..., Any],
        *args: Any,
        done: Callable[[Any], None] | None = None,
        read_only: bool = True,
        kwargs: dict[str, Any] | None = None,
        no_ws: bool = False,
        ws_db: bool = False,
        error: Callable[[AcetError], None] | None = None,
    ) -> None:
        kw = kwargs or {}
        path: Path | None

        def call_plain(*a: Any) -> Any:
            return fn(*a, **kw)

        def call_ws(ws: Any, *a: Any) -> Any:
            return fn(ws.db if ws_db else ws, *a, **kw)

        if no_ws or self.win.ws_path is None:
            call: Callable[..., Any] = call_plain
            path = None
        else:
            call = call_ws
            path = self.win.ws_path

        def on_error(err: AcetError, tb: str) -> None:
            if error is not None:
                error(err)
            else:
                self.win.show_error(err, tb)

        self.win.runner.run(call, *args, ws_path=path, read_only=read_only, on_done=done, on_error=on_error)

    def goto(self, title: str) -> None:
        self.win.goto(title)

    def open_build(self, build_id: str | None) -> None:
        self.goto("Builds")
        page = self.pages["Builds"]
        self.run(lambda ws: None, done=lambda _x: page.select_build(build_id))

    def open_import_wizard(self) -> None:
        self.win.open_import_wizard()

    def load_products(self, cb: Callable[[list[dict[str, Any]]], None]) -> None:
        from acet.application.views import products

        self.run(products, done=cb)

    def status(self, text: str) -> None:
        self.win.statusBar().showMessage(text, 10_000)

    def set_health(self, health: str) -> None:
        self.win.health.setText(f"Health: {health.replace('_', ' ')}")

    def refresh_current(self) -> None:
        w = self.win.stack.currentWidget()
        if isinstance(w, Page):
            w.refresh()

    def diagnostics(self) -> None:
        self.win.diagnostics()


class MainWindow(QMainWindow):
    def __init__(self, ws_path: Path | None) -> None:
        super().__init__()
        self.ws_path = ws_path
        self.setWindowTitle(f"ACET {acet.__version__}")
        self.resize(1280, 820)
        self.runner = TaskRunner(self)
        self.ctx = Context(self)
        central = QWidget()
        lay = QHBoxLayout(central)
        self.nav = QListWidget()
        self.nav.setAccessibleName("Navigation")
        self.nav.setMaximumWidth(190)
        self.stack = QStackedWidget()
        lay.addWidget(self.nav)
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        for i, cls in enumerate(PAGES):
            page = cls(self.ctx)
            self.ctx.pages[cls.title] = page
            self.stack.addWidget(page)
            item = QListWidgetItem(f"{cls.title}")
            item.setToolTip(f"Alt+{i + 1}" if i < 9 else cls.title)
            self.nav.addItem(item)
            if i < 9:
                QShortcut(QKeySequence(f"Alt+{i + 1}"), self, activated=lambda i=i: self.nav.setCurrentRow(i))
        self.nav.currentRowChanged.connect(self._switch)
        self.health = QLabel("Health: …")
        self.health.setAccessibleName("System health")
        self.jobs = QLabel("Jobs: 0")
        self.jobs.setAccessibleName("Active jobs")
        self.statusBar().addPermanentWidget(self.health)
        self.statusBar().addPermanentWidget(self.jobs)
        self.runner.busy_changed.connect(lambda n: self.jobs.setText(f"Background tasks: {n}"))
        QShortcut(QKeySequence("Ctrl+K"), self, activated=self.open_search)
        self._menus()
        self.nav.setCurrentRow(0)
        if self.ws_path is not None:
            self.after_open()

    def _menus(self) -> None:
        m = self.menuBar().addMenu("&File")
        for text, slot, sc in (
            ("&New workspace…", self.new_workspace, "Ctrl+N"),
            ("&Open workspace…", self.open_workspace, "Ctrl+O"),
            ("&Import build…", self.open_import_wizard, "Ctrl+I"),
            ("Import .&acetpack…", self.import_pack, None),
            ("&Quit", self.close, "Ctrl+Q"),
        ):
            a = QAction(text, self)
            if sc:
                a.setShortcut(QKeySequence(sc))
            a.triggered.connect(slot)
            m.addAction(a)
        h = self.menuBar().addMenu("&Help")
        about = QAction("&About ACET", self)
        about.triggered.connect(
            lambda: QMessageBox.about(
                self,
                "ACET",
                f"ACET {acet.__version__}\nAnti-Cheat Evolution Tracker.\nNo imported artifact is ever executed.",
            )
        )
        h.addAction(about)

    def _switch(self, row: int) -> None:
        if row < 0:
            return
        self.stack.setCurrentIndex(row)
        page = self.stack.widget(row)
        if isinstance(page, Page) and self.ws_path is not None:
            page.refresh()

    def goto(self, title: str) -> None:
        for i in range(self.stack.count()):
            if self.stack.widget(i).title == title:
                self.nav.setCurrentRow(i)
                return

    def open_search(self) -> None:
        SearchDialog(self).exec() if os.environ.get("QT_QPA_PLATFORM") != "offscreen" else SearchDialog(self).show()

    def open_import_wizard(self) -> None:
        from acet.ui.wizards import ImportWizard

        self._wizard = ImportWizard(self.ctx)
        self._wizard.show()

    def show_error(self, err: AcetError, tb: str) -> None:
        self.statusBar().showMessage(f"{err.code}: {err.spec.summary}", 15_000)
        dlg = ErrorDialog(err, tb, self, on_diagnostics=self.diagnostics)
        dlg.setModal(False)
        dlg.show()
        self._last_error = dlg

    def diagnostics(self) -> None:
        dest, _ = QFileDialog.getSaveFileName(self, "Diagnostic package", "acet-diagnostics.zip")
        if dest:
            from acet.platform.diagnostics import create_diagnostic_package

            self.ctx.run(create_diagnostic_package, Path(dest), done=lambda p: self.ctx.status(f"Diagnostics: {p}"))

    def after_open(self) -> None:
        """Startup: recover interrupted jobs and offer to resume them (ACC-010); compute health."""
        from acet.jobs.store import recover_interrupted

        def offer(ids: list[str]) -> None:
            if (
                ids
                and QMessageBox.question(
                    self, "Interrupted analyses", f"{len(ids)} analysis job(s) were interrupted. Resume now?"
                )
                == QMessageBox.StandardButton.Yes
            ):
                from acet.analysis.orchestrator import resume

                for jid in ids:
                    self.ctx.run(resume, jid, read_only=False, done=lambda s: self.ctx.status(f"Resumed: {s.status}"))

        self.ctx.run(recover_interrupted, read_only=False, ws_db=True, done=offer)
        self.ctx.pages["System"].refresh()
        settings = QSettings("ACET", "ACET")
        settings.setValue("last_workspace", str(self.ws_path))

    def set_workspace(self, path: Path) -> None:
        self.ws_path = path
        self.setWindowTitle(f"ACET {acet.__version__} — {path.name}")
        self.after_open()
        self.ctx.refresh_current()

    def new_workspace(self) -> None:
        from acet.ui.wizards import FirstRunWizard

        wiz = FirstRunWizard(self.ctx)
        if wiz.exec() and wiz.created is not None:
            self.set_workspace(wiz.created)

    def open_workspace(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Open workspace")
        if d:
            self.set_workspace(Path(d))

    def import_pack(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "Import .acetpack", filter="ACET pack (*.acetpack)")
        if f:
            from acet.reporting.acetpack import import_pack

            self.ctx.run(import_pack, Path(f), read_only=False, done=lambda r: self.ctx.status("Pack imported"))

    def closeEvent(self, event: Any) -> None:
        self.runner.wait(5000)
        super().closeEvent(event)


def resolve_initial_workspace() -> Path | None:
    env = os.environ.get("ACET_WORKSPACE")
    if env and (Path(env) / "acet.db").is_file():
        return Path(env)
    last = QSettings("ACET", "ACET").value("last_workspace")
    if last and (Path(str(last)) / "acet.db").is_file():
        return Path(str(last))
    return None


def main(argv: list[str] | None = None) -> int:
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("ACET")
    ws = resolve_initial_workspace()
    win = MainWindow(ws)
    win.show()
    if ws is None:
        win.new_workspace()
    return int(app.exec())
