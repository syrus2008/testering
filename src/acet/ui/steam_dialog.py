"""Older versions through the Steam client signed in on this PC (Watch page → “Older versions (Steam)…”).

The user picks an installed game and its depot, pastes the dated manifest list copied from SteamDB, ticks the
versions; for each one ACET copies the ``download_depot`` command and opens the Steam console (the only step left to
the user: paste and press Enter, so Steam downloads with the account already signed in), follows Steam's log, then
imports the anti-cheat files dated at the manifest date, keeps a copy and compares them with the installed version.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


def _size(n: int) -> str:
    return f"{n / 1024**3:.1f} GB" if n >= 1024**3 else f"{n / 1024**2:.0f} MB"


class SteamVersionsDialog(QDialog):
    POLL_MS = 3000

    def __init__(self, ctx: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Older versions (Steam)")
        self.setWindowModality(Qt.WindowModality.NonModal)  # the user switches to Steam while it runs
        self.games: list[dict[str, Any]] = []
        self.captured: set[str] = set()
        self.queue: list[dict[str, Any]] = []
        self.job: Any = None
        self.busy = False
        self.open_console: Callable[[], object] = lambda: QDesktopServices.openUrl(QUrl("steam://open/console"))
        lay = QVBoxLayout(self)
        self.account = QLabel("Looking for Steam…")
        self.account.setAccessibleName("Steam account")
        self.account.setWordWrap(True)
        lay.addWidget(self.account)
        row = QHBoxLayout()
        row.addWidget(QLabel("Game:"))
        self.game = QComboBox()
        self.game.setAccessibleName("Game")
        self.game.currentIndexChanged.connect(self.fill_depots)
        row.addWidget(self.game, 2)
        row.addWidget(QLabel("Depot:"))
        self.depot = QComboBox()
        self.depot.setAccessibleName("Depot")
        self.depot.currentIndexChanged.connect(self.parse)
        row.addWidget(self.depot, 2)
        self.steamdb = QPushButton("Open the SteamDB list")
        self.steamdb.clicked.connect(self.open_steamdb)
        row.addWidget(self.steamdb)
        lay.addLayout(row)
        lay.addWidget(
            QLabel(
                "Paste here the manifest list of this depot copied from SteamDB (select the table, "
                "Ctrl+C), or lines “date  manifest id”:"
            )
        )
        self.paste = QPlainTextEdit()
        self.paste.setAccessibleName("Pasted manifest list")
        self.paste.setMaximumHeight(110)
        self.paste.textChanged.connect(self.parse)
        lay.addWidget(self.paste)
        self.versions = QListWidget()
        self.versions.setAccessibleName("Versions found")
        lay.addWidget(self.versions, 1)
        self.keep = QCheckBox("Delete Steam's full download once the anti-cheat files are copied (recommended)")
        self.keep.setChecked(True)
        lay.addWidget(self.keep)
        self.state = QLabel("")
        self.state.setAccessibleName("Download status")
        self.state.setWordWrap(True)
        self.state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.state)
        buttons = QHBoxLayout()
        self.start = QPushButton("&Download and import the ticked versions")
        self.start.clicked.connect(self.start_queue)
        self.again = QPushButton("Copy the &command again")
        self.again.clicked.connect(self.hand_to_steam)
        self.finished_btn = QPushButton("Steam has &finished")
        self.finished_btn.setToolTip("Use it if ACET did not notice the end of the download in Steam's log.")
        self.finished_btn.clicked.connect(self.user_says_finished)
        self.stop = QPushButton("&Stop after this one")
        self.stop.clicked.connect(self.stop_queue)
        for b in (self.start, self.again, self.finished_btn, self.stop):
            buttons.addWidget(b)
        buttons.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        lay.addLayout(buttons)
        self.timer = QTimer(self)
        self.timer.setInterval(self.POLL_MS)
        self.timer.timeout.connect(self.poll)
        self._running(False)
        self.resize(860, 560)
        self.load()

    # ------------------------------------------------------------ data
    def load(self) -> None:
        from acet.application import steam_history as sh

        def read(ws: Any) -> dict[str, Any]:
            return {
                "account": sh.signed_in_account(),
                "games": sh.installed_games(),
                "captured": sh.captured_manifests(ws),
            }

        def failed(exc: Any) -> None:
            self.account.setText(f"Steam: {exc}")
            self.start.setEnabled(False)

        self.ctx.run(read, read_only=True, done=self.show_data, error=failed)

    def show_data(self, data: dict[str, Any]) -> None:
        acc, self.games, self.captured = data["account"], data["games"], data["captured"]
        who = acc.get("persona") or acc.get("account")
        if acc.get("running") is False:
            text = "⚠ Steam is not running or nobody is signed in: start Steam and sign in, then use this window."
        elif who:
            text = f"Steam: signed in as {who}. Downloads use this account through Steam itself (no password here)."
        else:
            text = "Steam found; sign in to Steam on this PC (downloads use the account signed in to Steam)."
        self.account.setText(text)
        self.game.blockSignals(True)
        self.game.clear()
        for g in self.games:
            self.game.addItem(f"{g['name']} — {', '.join(g['products'])}", g)
        self.game.blockSignals(False)
        if not self.games:
            self.state.setText("No installed Steam game with an anti-cheat folder listed in the watch presets.")
        self.fill_depots()

    def fill_depots(self) -> None:
        g = self.game.currentData()
        self.depot.blockSignals(True)
        self.depot.clear()
        for d in (g or {}).get("depots", []):
            self.depot.addItem(f"{d['depot']} ({_size(d['size'])}, installed manifest {d['manifest']})", d)
        self.depot.blockSignals(False)
        self.parse()

    def open_steamdb(self) -> None:
        from acet.application import steam_history as sh

        d = self.depot.currentData()
        if d:
            QDesktopServices.openUrl(QUrl(sh.steamdb_url(d["depot"])))

    def parse(self) -> None:
        from acet.application import steam_history as sh

        d = self.depot.currentData() or {}
        self.versions.clear()
        for r in sh.parse_manifest_list(self.paste.toPlainText()):
            note = ""
            if r["manifest"] == d.get("manifest"):
                note = "  (installed now)"
            elif r["manifest"] in self.captured:
                note = "  (already imported)"
            item = QListWidgetItem(
                f"{(r['date'] or 'date unknown')[:16].replace('T', ' ')}   manifest {r['manifest']}{note}"
            )
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, r)
            self.versions.addItem(item)

    def ticked(self) -> list[dict[str, Any]]:
        out = []
        for i in range(self.versions.count()):
            it = self.versions.item(i)
            if it.checkState() == Qt.CheckState.Checked:
                out.append(it.data(Qt.ItemDataRole.UserRole))
        return out

    # ------------------------------------------------------------ the queue
    def _running(self, on: bool) -> None:
        self.start.setEnabled(not on)
        for b in (self.again, self.finished_btn, self.stop):
            b.setEnabled(on)

    def start_queue(self) -> None:
        g, d = self.game.currentData(), self.depot.currentData()
        picks = self.ticked()
        if not g or not d or not picks:
            self.state.setText("Choose a game, a depot and tick at least one version.")
            return
        self.queue = [{"game": g, "depot": d, **r} for r in picks]
        self._running(True)
        self.next_version()

    def stop_queue(self) -> None:
        self.queue = []
        if self.job is None:
            self._running(False)
        self.state.setText(self.state.text() + "\nStopping after the current version.")

    def next_version(self) -> None:
        from acet.application import steam_history as sh

        if not self.queue:
            self.job = None
            self.timer.stop()
            self._running(False)
            return
        item = self.queue.pop(0)
        g = item["game"]

        def started(job: Any) -> None:
            self.job = job
            self.hand_to_steam()
            self.timer.start()

        def failed(exc: Any) -> None:
            self.state.setText(f"Manifest {item['manifest']}: {exc}")
            QTimer.singleShot(0, self.next_version)

        self.ctx.run(
            sh.begin,
            g["appid"],
            g["name"],
            item["depot"]["depot"],
            item["manifest"],
            item["date"],
            read_only=False,
            done=started,
            error=failed,
        )

    def hand_to_steam(self) -> None:
        """The only manual step: Steam's console receives the command from the user (Ctrl+V, Enter)."""
        if self.job is None:
            return
        QGuiApplication.clipboard().setText(self.job.command)
        self.open_console()
        left = f" ({len(self.queue)} more after this one)" if self.queue else ""
        self.state.setText(
            f"Version {(self.job.date or '')[:10]} (manifest {self.job.manifest}){left}:\n"
            f"In the Steam console that just opened, press Ctrl+V then Enter. The command is in the clipboard:\n"
            f"    {self.job.command}\n"
            "Steam downloads with your account; ACET notices the end by itself (the whole depot is downloaded, "
            "it can take a while)."
        )

    def poll(self) -> None:
        from acet.application import steam_history as sh

        if self.job is None or self.busy:
            return
        self.busy = True

        def checked(job: Any) -> None:
            self.busy = False
            self.job = job
            if job.status == "DOWNLOADED":
                self.capture()
            elif job.status == "FAILED":
                self.timer.stop()
                self.state.setText(f"Steam could not download manifest {job.manifest}: {job.detail}")
                self.job = None
                QTimer.singleShot(0, self.next_version)

        def failed(exc: Any) -> None:
            self.busy = False

        self.ctx.run(sh.poll, self.job.id, read_only=False, done=checked, error=failed)

    def user_says_finished(self) -> None:
        from acet.application import steam_history as sh

        if self.job is not None:
            self.ctx.run(sh.mark_downloaded, self.job.id, read_only=False, done=lambda _j: self.capture())

    def capture(self) -> None:
        from acet.application import steam_history as sh

        self.timer.stop()
        job = self.job
        if job is None:
            return
        self.state.setText(f"Steam finished: importing the anti-cheat files of {(job.date or '')[:10]}…")

        def done(j: Any) -> None:
            self.job = None
            if j.status == "CAPTURED":
                self.captured.add(j.manifest)
                msg = f"Imported {j.game} {(j.date or '')[:10]} (manifest {j.manifest}): {j.detail}"
                msg += "".join(f"\n  {c}" for c in j.compared)
            else:
                msg = f"Manifest {j.manifest}: {j.detail}"
            self.state.setText(msg)
            self.ctx.status(msg.splitlines()[0])
            self.parse()
            self.next_version()

        def failed(exc: Any) -> None:
            self.job = None
            self.state.setText(f"Import of manifest {job.manifest} failed: {exc}")
            self.next_version()

        self.ctx.run(
            sh.capture,
            job.id,
            read_only=False,
            done=done,
            error=failed,
            kwargs={"delete_download": self.keep.isChecked()},
        )

    def closeEvent(self, event: Any) -> None:
        self.queue = []
        self.timer.stop()
        super().closeEvent(event)
