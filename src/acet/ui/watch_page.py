"""Watch page: follow the versions of locally installed binaries (e.g. an anti-cheat) and import each new one."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from acet.ui.pages import Page
from acet.ui.widgets import Table

STATUS_TEXT = {
    "NEW_VERSION": "★ NEW VERSION",
    "UNCHANGED": "✔ unchanged",
    "LOCKED": "⚠ LOCKED (retry later)",
    "UNSTABLE": "⚠ UPDATE IN PROGRESS (retry later)",
    "EMPTY": "✖ no executable",
    "ERROR": "✖ ERROR",
    "DISABLED": "⏸ disabled",
    None: "never checked",
}


class DetectDialog(QDialog):
    """Suggested locations, unticked by default: nothing is watched without the user's choice."""

    def __init__(self, candidates: list[dict[str, Any]], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Detected installations")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Tick the folders to watch. ACET only reads them; nothing is executed or modified."))
        self.list = QListWidget()
        self.list.setAccessibleName("Detected installations")
        for c in candidates:
            item = QListWidgetItem(f"{c['label']}\n{c['paths'][0]}")
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, c)
            self.list.addItem(item)
        if not candidates:
            lay.addWidget(QLabel("Nothing found in the usual locations. Use “Add folder…” instead."))
        lay.addWidget(self.list)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        self.resize(640, 380)

    def chosen(self) -> list[dict[str, Any]]:
        out = []
        for i in range(self.list.count()):
            it = self.list.item(i)
            if it.checkState() == Qt.CheckState.Checked:
                out.append(it.data(Qt.ItemDataRole.UserRole))
        return out


class WatchPage(Page):
    title = "Watch"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self.scanning = False
        self.ask_detect: Callable[[QDialog], bool] = lambda dlg: bool(dlg.exec())  # tests: non-blocking chooser
        lay = QVBoxLayout(self)
        lay.addWidget(
            QLabel(
                "Automatic: ACET finds the installations (e.g. an anti-cheat) on this PC, checks them at start-up and "
                "regularly, keeps a copy of every new version in the versions folder, imports it and compares it with "
                "the previous one. Files are only read, never executed or modified."
            )
        )
        row = QHBoxLayout()
        row.addWidget(self.button("&Check now", self.scan_now, "F5"))
        row.addWidget(self.button("Compare &last two versions", self.compare_last))
        row.addWidget(self.button("Open &versions folder", self.open_archive))
        row.addWidget(self.button("&Add folder…", self.add_folder))
        row.addWidget(self.button("&Detect…", self.detect))
        row.addWidget(self.button("Enable / &disable", self.toggle))
        row.addWidget(self.button("&Remove", self.remove))
        row.addStretch()
        lay.addLayout(row)
        opts = QHBoxLayout()
        self.discover = QCheckBox("Find installations automatically")
        self.auto = QCheckBox("Check every")
        self.auto.setAccessibleName("Automatic checks")
        self.interval = QSpinBox()
        self.interval.setRange(5, 24 * 60)
        self.interval.setSuffix(" min")
        self.interval.setAccessibleName("Check interval in minutes")
        self.compare = QCheckBox("Compare each new version automatically")
        self.background = QCheckBox("Also when ACET is closed (Windows)")
        self.background.setEnabled(sys.platform == "win32")
        self.background.setToolTip("Registers a Windows scheduled task for your account (no administrator rights).")
        for w in (self.discover, self.auto, self.interval, self.compare, self.background):
            opts.addWidget(w)
        opts.addStretch()
        lay.addLayout(opts)
        arch = QHBoxLayout()
        self.archive = QLabel("")
        self.archive.setAccessibleName("Versions folder")
        self.archive.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        arch.addWidget(QLabel("Versions folder:"))
        arch.addWidget(self.archive, 1)
        arch.addWidget(self.button("C&hange…", self.change_archive))
        lay.addLayout(arch)
        self.state = QLabel("")
        self.state.setAccessibleName("Watch status")
        self.state.setWordWrap(True)
        lay.addWidget(self.state)
        split = QSplitter(Qt.Orientation.Vertical)
        self.sources = Table(
            [
                ("label", "Source"),
                ("product", "Product"),
                ("status_text", "Last check"),
                ("last_checked_at", "Checked at"),
                ("last_changed_at", "Last new version"),
                ("versions", "Versions"),
                ("paths_text", "Folders"),
                ("last_detail", "Detail"),
            ],
            "Watched sources",
        )
        self.sources.fit_columns("paths_text")
        self.sources.view.selectionModel().currentRowChanged.connect(lambda *_: self.show_history())
        self.history = Table(
            [
                ("at", "Detected at"),
                ("release", "Build label"),
                ("files", "Files"),
                ("kind", "Kind"),
                ("archive_path", "Copy of the files"),
                ("build_id", "Build id"),
            ],
            "Versions of the selected source",
        )
        split.addWidget(self.sources)
        split.addWidget(self.history)
        lay.addWidget(split, 1)
        self.history.view.doubleClicked.connect(lambda _i: self.open_selected_version())
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.auto_scan)
        for box in (self.auto, self.discover, self.compare):
            box.toggled.connect(self.save_auto)
        self.background.toggled.connect(self.save_background)
        self.interval.editingFinished.connect(self.save_auto)
        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(300)
        self.save_timer.timeout.connect(self._write_options)
        self.loaded = False
        self.started = False  # the first automatic cycle runs once, at start-up
        QTimer.singleShot(0, self.refresh)  # load the schedule at start-up, not only when the page is opened

    # ------------------------------------------------------------ data
    def refresh(self) -> None:
        from acet.application import watch

        def load(ws: Any) -> dict[str, Any]:
            return {"state": watch.load_state(ws), "sources": watch.list_sources(ws),
                    "archive": str(watch.archive_dir(ws))}  # fmt: skip

        self.ctx.run(load, done=self.display, read_only=True)

    def display(self, data: dict[str, Any]) -> None:
        state, sources = data["state"], data["sources"]
        self.rows = sources
        self.sources.set_rows(
            [
                {
                    "id": s.id,
                    "label": s.label + ("" if s.enabled else " (disabled)"),
                    "product": s.product,
                    "status_text": STATUS_TEXT.get(s.last_status, s.last_status),
                    "last_checked_at": (s.last_checked_at or "")[:19].replace("T", " "),
                    "last_changed_at": (s.last_changed_at or "")[:19].replace("T", " "),
                    "versions": len({h["build_id"] for h in s.history}),
                    "paths_text": "\n".join(s.paths),
                    "last_detail": s.last_detail or "",
                }
                for s in sources
            ]
        )
        for box, key in ((self.auto, "auto"), (self.discover, "auto_discover"), (self.compare, "auto_compare"),
                         (self.background, "background_task")):  # fmt: skip
            box.blockSignals(True)
            box.setChecked(bool(state.get(key)))
            box.blockSignals(False)
        self.interval.blockSignals(True)
        self.interval.setValue(int(state["interval_minutes"]))
        self.interval.blockSignals(False)
        self.archive.setText(data["archive"])
        self.loaded = True
        self.apply_schedule()
        self.show_history()
        if not self.started and self.auto.isChecked():
            self.started = True
            QTimer.singleShot(0, lambda: self._scan(None, automatic=True))  # first automatic round at start-up

    def selected(self) -> Any:
        sel = self.sources.selected()
        return next((s for s in getattr(self, "rows", []) if sel and s.id == sel["id"]), None)

    def show_history(self) -> None:
        s = self.selected()
        rows = []
        if s is not None:
            for h in reversed(s.history):
                rows.append({**h, "archive_path": h.get("archive_path") or "", "at": h["at"][:19].replace("T", " "),
                             "kind": "new build" if h.get("new_build") else "seen before (same bytes)"})  # fmt: skip
        self.history.set_rows(rows)

    # ------------------------------------------------------------ actions
    def detect(self) -> None:
        from acet.application import watch

        def chosen(cands: list[dict[str, Any]]) -> None:
            dlg = DetectDialog(cands, self)
            if not self.ask_detect(dlg):
                return
            picks = dlg.chosen()
            if picks:

                def add_all(ws: Any) -> int:
                    for c in picks:
                        watch.add_source(ws, c["label"], c["product"], c["paths"])
                    return len(picks)

                self.ctx.run(
                    add_all, read_only=False, done=self.after(lambda n: f"Watching {n} new source(s)", self.refresh)
                )

        self.ctx.run(watch.detect_candidates, no_ws=True, done=chosen)

    def add_folder(self, folder: str | None = None, product: str | None = None) -> None:
        from acet.application import watch

        if folder is None:
            folder = QFileDialog.getExistingDirectory(self, "Folder to watch")
        if not folder:
            return
        if product is None:
            product, ok = QInputDialog.getText(self, "Product", "Product name for this folder:", text=Path(folder).name)
            if not ok or not product.strip():
                return
        label = f"{Path(folder).parent.name} — {Path(folder).name}" if Path(folder).parent.name else Path(folder).name
        self.ctx.run(watch.add_source, label, product.strip(), [folder], read_only=False,
                     done=self.after(lambda s: f"Watching {s.label}", self.refresh))  # fmt: skip

    def remove(self) -> None:
        from acet.application import watch

        s = self.selected()
        if s is not None:
            self.ctx.run(watch.remove_source, s.id, read_only=False, done=lambda _x: self.refresh())

    def toggle(self) -> None:
        from acet.application import watch

        s = self.selected()
        if s is not None:
            self.ctx.run(watch.set_enabled, s.id, not s.enabled, read_only=False, done=lambda _x: self.refresh())

    def scan_now(self) -> None:
        """The same full round as the automatic one (discover, check, copy, import, compare), right now."""
        self._scan(None, automatic=True)

    def auto_scan(self) -> None:
        if self.auto.isChecked():
            self._scan(None, automatic=True)

    def _scan(self, ids: list[str] | None, *, automatic: bool = False) -> None:
        from acet.application import watch

        if self.scanning:
            return
        self.scanning = True
        self.state.setText("Looking for installations and new versions…" if automatic else "Checking…")

        def run(ws: Any) -> dict[str, Any]:
            if ids is not None:
                return {"added": [], "results": [watch.scan_source(ws, i) for i in ids], "compared": []}
            if automatic:
                return watch.run_cycle(ws)
            return {"added": [], "results": watch.scan_all(ws), "compared": []}

        def done(cycle: dict[str, Any]) -> None:
            self.scanning = False
            results = cycle["results"]
            new = [r for r in results if r.status == "NEW_VERSION" and r.created_build]
            problems = [r for r in results if r.status in ("LOCKED", "UNSTABLE", "ERROR", "EMPTY")]
            parts = [f"now watching {', '.join(cycle['added'])}"] if cycle["added"] else []
            parts.append(", ".join(f"NEW VERSION of {r.label}" for r in new) if new else "no new version")
            parts += [c for c in cycle["compared"]]
            if problems:
                parts.append(f"{len(problems)} source(s) will be retried")
            msg = "; ".join(parts)
            self.state.setText(f"Last check ({'automatic' if automatic else 'manual'}): {msg}.")
            self.ctx.status(("Watch: " if automatic else "Check: ") + msg)
            self.refresh()

        def failed(exc: Any) -> None:
            self.scanning = False
            self.state.setText(f"Check failed: {exc}")

        self.ctx.run(run, read_only=False, done=done, error=failed)

    def save_auto(self) -> None:
        """Debounced: rapid changes give one write with the final values (two background writes could finish in
        the wrong order and restore an old value)."""
        if not self.loaded:
            return
        self.apply_schedule()
        self.save_timer.start()

    def _write_options(self) -> None:
        from acet.application import watch

        auto, minutes = self.auto.isChecked(), self.interval.value()
        discover, compare = self.discover.isChecked(), self.compare.isChecked()

        def save(ws: Any) -> None:
            watch.set_interval(ws, minutes)
            watch.set_option(ws, "auto", auto)
            watch.set_option(ws, "auto_discover", discover)
            watch.set_option(ws, "auto_compare", compare)

        self.ctx.run(save, read_only=False, done=lambda _x: None)

    def save_background(self, enabled: bool) -> None:
        from acet.application import watch

        if not self.loaded:
            return

        def failed(exc: Any) -> None:
            self.state.setText(f"Background checks: {exc}")
            self.refresh()

        self.ctx.run(watch.set_background_task, enabled, read_only=False, error=failed,
                     done=lambda _x: self.state.setText("Background checks " + ("on" if enabled else "off")))  # fmt: skip

    def change_archive(self) -> None:
        from acet.application import watch

        folder = QFileDialog.getExistingDirectory(self, "Folder where each version is copied", self.archive.text())
        if folder:
            self.ctx.run(watch.set_option, "archive_dir", folder, read_only=False, done=lambda _x: self.refresh())

    def open_archive(self) -> None:
        path = Path(self.archive.text())
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def open_selected_version(self) -> None:
        row = self.history.selected()
        if row and row.get("archive_path"):
            QDesktopServices.openUrl(QUrl.fromLocalFile(row["archive_path"]))

    def apply_schedule(self) -> None:
        if self.auto.isChecked():
            self.timer.start(self.interval.value() * 60_000)
        else:
            self.timer.stop()

    def compare_last(self) -> None:
        from acet.application import watch

        s = self.selected()
        pair = watch.last_two_builds(s) if s is not None else None
        if pair is None:
            self.state.setText("Select a source with at least two different versions.")
            return
        page = self.ctx.pages["Compare"]
        self.ctx.goto("Compare")
        page.preselect(*pair)
