"""Engine Pack Manager UI (ADR-0013): toolbar status button, manager view (shared by the dialog and Settings →
Analysis Engines), consent, progress/cancel, first-run guide, profile gating.

Everything slow (index, download, hashing, extraction, doctor) runs through the existing TaskRunner; progress
reaches the Qt thread through a signal. State is always shown as text + symbol, never by colour alone.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QSettings, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from acet.domain.error_codes import AcetError
from acet.ui.widgets import Table

# State → (symbol, label). The symbol and the word carry the meaning; colour is only decoration.
STATE_DISPLAY = {
    "READY": ("✔", "READY"),
    "DEGRADED": ("⚠", "DEGRADED"),
    "NOT_INSTALLED": ("⚠", "NOT INSTALLED"),
    "UPDATE_AVAILABLE": ("⬆", "UPDATE AVAILABLE"),
    "VERIFYING": ("⟳", "VERIFYING"),
    "INSTALLING": ("⟳", "INSTALLING"),
    "REPAIR_REQUIRED": ("✖", "REPAIR REQUIRED"),
    "CORRUPTED": ("✖", "CORRUPTED"),
    "REVOKED": ("✖", "REVOKED"),
    "OFFLINE": ("⚠", "OFFLINE"),
    "UNVERIFIED": ("?", "UNVERIFIED"),
    "DEVELOPER": ("⚠", "DEVELOPER CONFIGURATION"),
    "UNAVAILABLE": ("✖", "UNAVAILABLE"),
}
FAST_ONLY_KEY = "engines/continue_fast_only"


def _exec(box: QMessageBox) -> Any:
    return box.exec()


MODAL_EXEC: Callable[[QMessageBox], Any] = _exec  # tests substitute a non-blocking chooser


def state_text(state: str) -> str:
    sym, label = STATE_DISPLAY.get(state, ("?", state.replace("_", " ")))
    return f"{sym} {label}"


class _Bridge(QObject):
    progress = Signal(str, int, object, str)


class EngineStatusButton(QToolButton):
    """Always-visible toolbar control: "Engines: ⚠ DEGRADED"; click opens the Engine Pack Manager."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = "UNVERIFIED"
        self.setAccessibleName("Analysis engines")
        self.set_state("VERIFYING")

    def set_state(self, state: str) -> None:
        self.state = state
        self.setText(f"Engines: {state_text(state)}")
        self.setAccessibleDescription(f"Analysis engines status: {STATE_DISPLAY.get(state, ('', state))[1]}")
        self.setToolTip("Open the Engine Pack Manager (install, verify, repair analysis engines)")


class ConsentDialog(QDialog):
    """Shown before any significant download: version, sizes, components and licenses."""

    def __init__(self, entry: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("ACET Engine Pack")
        lay = QVBoxLayout(self)
        mb = 1024**2
        comps = "\n".join(
            f"- {c.get('name', c.get('id'))} {c.get('version', '')} — {c.get('license', '')}"
            for c in entry.get("components") or []
        )
        lic = "\n".join(
            f"- {x['component']}: {x['spdx']} ({x.get('bundling', '')})" for x in entry.get("licenses") or []
        )
        text = (
            f"Engine Pack {entry['id']} {entry['version']}\n\n"
            f"Download size: {int(entry['archive_size']) / mb:.0f} MB\n"
            f"Installed size: {int(entry.get('installed_size') or 0) / mb:.0f} MB\n"
            f"Source: {entry.get('_index_url', '')}\n\n"
            f"Components:\n{comps or '- (see licenses)'}\n\nLicenses:\n{lic}\n\n"
            "The package is verified (signature, SHA-256, every file) before anything is activated. "
            "Nothing is installed outside ACET's own folder; Windows settings, JAVA_HOME and PATH are not changed."
        )
        body = QPlainTextEdit(text)
        body.setReadOnly(True)
        body.setAccessibleName("Engine Pack details and licenses")
        lay.addWidget(body)
        box = QDialogButtonBox()
        self.install_btn = box.addButton("&Install", QDialogButtonBox.ButtonRole.AcceptRole)
        box.addButton("&Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)
        self.resize(560, 460)


class EngineManagerWidget(QWidget):
    """The one implementation of the Engine Pack Manager view (dialog and Settings embed it)."""

    state_changed = Signal(str)

    def __init__(
        self, ctx: Any, parent: QWidget | None = None, *, ask: Callable[[QDialog], bool] | None = None
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.ask = ask or (lambda dlg: bool(dlg.exec()))
        self.cancel_event: threading.Event | None = None
        self.last_status: dict[str, Any] | None = None
        self.busy = False
        self.offline = False
        self.bridge = _Bridge()
        self.bridge.progress.connect(self._on_progress)
        lay = QVBoxLayout(self)
        self.summary = QLabel("Engine Pack: …")
        self.summary.setAccessibleName("Engine Pack status")
        self.summary.setWordWrap(True)
        lay.addWidget(self.summary)
        self.profiles = Table([("profile", "Profile"), ("state_text", "Status"), ("detail", "Detail")], "Profiles")
        self.profiles.setMaximumHeight(170)
        lay.addWidget(self.profiles)
        self.components = Table(
            [
                ("label", "Component"),
                ("role", "Role"),
                ("state_text", "Status"),
                ("version", "Version"),
                ("source", "Source"),
                ("why", "Why is this needed?"),
            ],
            "Engine components",
        )
        lay.addWidget(self.components, 1)
        prog = QGroupBox("Progress")
        pl = QVBoxLayout(prog)
        self.step = QLabel("Idle")
        self.step.setAccessibleName("Current step")
        self.bar = QProgressBar()
        self.bar.setAccessibleName("Installation progress")
        self.bar.setTextVisible(True)
        self.cancel_btn = QPushButton("&Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel)
        pl.addWidget(self.step)
        row = QHBoxLayout()
        row.addWidget(self.bar, 1)
        row.addWidget(self.cancel_btn)
        pl.addLayout(row)
        self.error = QLabel("")
        self.error.setWordWrap(True)
        self.error.setAccessibleName("Last error")
        pl.addWidget(self.error)
        lay.addWidget(prog)
        buttons = QHBoxLayout()
        self.install_btn = self._button(buttons, "&Install Engine Pack", self.install)
        self.file_btn = self._button(buttons, "Install from &file…", self.install_from_file)
        self.verify_btn = self._button(buttons, "&Verify", self.verify)
        self.repair_btn = self._button(buttons, "&Repair", self.repair)
        self.update_btn = self._button(buttons, "Check for &updates", self.install)
        self.diag_btn = self._button(buttons, "Open &diagnostics", self.diagnostics)
        lay.addLayout(buttons)
        self.retry: Callable[[], None] | None = None

    def _button(self, row: QHBoxLayout, text: str, slot: Callable[[], None]) -> QPushButton:
        b = QPushButton(text)
        b.clicked.connect(slot)
        row.addWidget(b)
        return b

    # ------------------------------------------------------------------ status
    def refresh(self) -> None:
        from acet.platform import engine_manager as em

        def load() -> dict[str, Any]:
            em.recover()
            return em.status()

        self.ctx.run(load, no_ws=True, done=self.show_status, error=self._failed)

    def show_status(self, st: dict[str, Any]) -> None:
        self.last_status = st
        pack = st["pack"]
        ver = st.get("verification") or {}
        last = (ver.get("last_verify") or {}).get("at") or ver.get("verified_at")
        self.summary.setText(
            (f"Engine Pack {pack['id']} {pack['version']} — {state_text(st['state'])}" if pack
             else f"Engine Pack — NOT INSTALLED  (analysis engines: {state_text(st['state'])})")
            + f"\nInstall location: {st['install_location']}"
            + (f"\nLast verification: {last} ({ver.get('verdict')})" if pack else "")
            + f"\nLog: {st['log']}"
        )  # fmt: skip
        self.profiles.set_rows(
            [
                {
                    "profile": name,
                    "state_text": state_text(p["state"]),
                    "detail": ("Engine Pack required: " + ", ".join(p["missing_required"]) if p["missing_required"]
                               else ("optional missing: " + ", ".join(p["missing_optional"]) if p["missing_optional"]
                                     else ("not health-checked: " + ", ".join(p["unverified"]) if p["unverified"]
                                           else "available"))),
                }
                for name, p in st["profiles"].items()
            ]
        )  # fmt: skip
        self.components.set_rows(
            [{**c, "state_text": state_text(c["state"]), "role": c["role"]} for c in st["components"]]
        )
        installed = pack is not None
        self.verify_btn.setEnabled(installed and not self.busy)
        self.repair_btn.setEnabled(installed and not self.busy and st["state"] in ("REPAIR_REQUIRED", "CORRUPTED"))
        self.install_btn.setEnabled(not self.busy)
        self.file_btn.setEnabled(not self.busy)
        self.update_btn.setEnabled(installed and not self.busy)
        self.state_changed.emit("OFFLINE" if self.offline and st["state"] != "READY" else st["state"])

    # ------------------------------------------------------------------ jobs
    def _start(self, state: str, label: str) -> threading.Event:
        self.busy = True
        self.error.setText("")
        self.step.setText(label)
        self.bar.setRange(0, 0)
        self.cancel_event = threading.Event()
        self.cancel_btn.setEnabled(True)
        for b in (self.install_btn, self.file_btn, self.verify_btn, self.repair_btn, self.update_btn):
            b.setEnabled(False)
        self.state_changed.emit(state)
        return self.cancel_event

    def _progress_fn(self) -> Callable[[str, int, int | None, str], None]:
        def emit(step: str, done: int, total: int | None, msg: str) -> None:
            self.bridge.progress.emit(step, done, total, msg)

        return emit

    def _on_progress(self, step: str, done: int, total: Any, msg: str) -> None:
        if total:
            self.bar.setRange(0, 1000)
            self.bar.setValue(int(1000 * done / total))
            mb = 1024**2
            extra = f"   {done / mb:.0f} MB / {total / mb:.0f} MB" if step == "download" else ""
            self.step.setText(f"{msg}{extra}")
        else:
            self.bar.setRange(0, 0)
            self.step.setText(msg)

    def _finished(self, res: Any) -> None:
        self.busy = False
        self.offline = False
        self.cancel_btn.setEnabled(False)
        self.bar.setRange(0, 1)
        self.bar.setValue(1)
        state = getattr(res, "state", None) or (res.get("state") if isinstance(res, dict) else None)
        self.step.setText({"CANCELLED": "CANCELLED — the previous state is unchanged"}.get(str(state), str(state)))
        if isinstance(res, dict) and res.get("problems"):
            self.error.setText("\n".join(res["problems"][:8]) + (f"\n{res['message']}" if res.get("message") else ""))
        self.refresh()

    def _failed(self, err: AcetError) -> None:
        self.busy = False
        self.cancel_btn.setEnabled(False)
        self.bar.setRange(0, 1)
        self.bar.setValue(0)
        reason = err.data.get("reason") or err.code
        self.step.setText(f"FAILED — {reason}  (Retry, or Install from file…)")
        self.error.setText(
            f"{reason} ({err.code}): {err.detail or err.spec.summary}\n{err.spec.impact}\n{err.spec.action}"
        )
        self.offline = reason in ("NETWORK_UNAVAILABLE", "TLS_ERROR", "PROXY_REQUIRED", "NO_DISTRIBUTION")
        self.refresh()

    def cancel(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.step.setText("Cancelling…")

    # ------------------------------------------------------------------ actions
    def install(self) -> None:
        from acet.platform import engine_manager as em

        self._start("VERIFYING", "Resolving the compatible Engine Pack…")
        self.retry = self.install

        def got(entry: dict[str, Any]) -> None:
            if not self.ask(ConsentDialog(entry, self)):
                self._finished({"state": "CANCELLED"})
                return
            cancel = self._start("INSTALLING", "Downloading…")
            self.ctx.run(
                em.install_entry, entry, no_ws=True, done=self._finished, error=self._failed,
                kwargs={"progress": self._progress_fn(), "cancel": cancel},
            )  # fmt: skip

        self.ctx.run(em.resolve_from_distribution, no_ws=True, done=got, error=self._failed)

    def install_from_file(self, path: str | None = None) -> None:
        from acet.platform import engine_manager as em

        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self, "Install Engine Pack from file", filter="Engine Pack (*.acetengine)"
            )
        if not path:
            return
        cancel = self._start("INSTALLING", "Verifying package…")
        self.ctx.run(
            em.install_archive, Path(path), no_ws=True, done=self._finished, error=self._failed,
            kwargs={"progress": self._progress_fn(), "cancel": cancel, "source": "file"},
        )  # fmt: skip

    def verify(self) -> None:
        from acet.platform import engine_manager as em

        self._start("VERIFYING", "Verifying signature, files and engines (doctor)…")
        self.ctx.run(em.verify_active, no_ws=True, done=self._finished, error=self._failed, kwargs={"health": True})

    def repair(self) -> None:
        from acet.platform import engine_manager as em

        cancel = self._start("INSTALLING", "Repairing…")
        self.ctx.run(
            em.repair, no_ws=True, done=self._finished, error=self._failed,
            kwargs={"progress": self._progress_fn(), "cancel": cancel},
        )  # fmt: skip

    def diagnostics(self) -> None:
        self.ctx.diagnostics()


class EngineManagerDialog(QDialog):
    def __init__(self, ctx: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Analysis Engines — Engine Pack Manager")
        self.resize(940, 640)
        lay = QVBoxLayout(self)
        self.manager = EngineManagerWidget(ctx, self)
        lay.addWidget(self.manager)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        lay.addWidget(close)
        self.manager.refresh()


class EngineWelcomeDialog(QDialog):
    """First launch without a valid Engine Pack: a guided choice, not a list of errors."""

    def __init__(self, ctx: Any, parent: QWidget | None = None, on_manage: Callable[[str], None] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("ACET Analysis Engines")
        self.on_manage = on_manage
        lay = QVBoxLayout(self)
        lay.addWidget(
            QLabel(
                "ACET works: importing, FAST analysis, reports and search are ready.\n\n"
                "The advanced analysis engines (STANDARD and DEEP profiles) are not installed yet.\n"
                "ACET can install its verified Engine Pack for you — no Java, Ghidra or settings to configure.\n\n"
                "Core / FAST analysis      ✔ Ready\n"
                "Advanced analysis         ✖ Engine Pack not installed"
            )
        )
        row = QHBoxLayout()
        for text, action in (
            ("&Install Engine Pack", "install"),
            ("Install from &file…", "file"),
            ("&Continue with FAST only", "fast"),
        ):
            b = QPushButton(text)
            b.clicked.connect(lambda _c=False, a=action: self.choose(a))
            row.addWidget(b)
        lay.addLayout(row)

    def choose(self, action: str) -> None:
        if action == "fast":
            QSettings("ACET", "ACET").setValue(FAST_ONLY_KEY, True)
        elif self.on_manage:
            self.on_manage(action)
        self.accept()


def gate_profile(
    parent: QWidget,
    ctx: Any,
    profile: str,
    run: Callable[[str], None],
    open_manager: Callable[[], None],
    *,
    ask: Callable[[QMessageBox], Any] | None = None,
) -> None:
    """Before an analysis: if the profile's engines are unavailable, offer Install / Use FAST / Cancel instead
    of failing. Degraded profiles run (missing evidence is reported)."""
    from acet.platform import engine_manager as em

    def decide(gate: dict[str, Any]) -> None:
        if gate["state"] != "UNAVAILABLE":
            run(profile)
            return
        name = profile.split("@", 1)[0]
        box = QMessageBox(parent)
        box.setWindowTitle(f"{name} analysis unavailable")
        box.setText(f"{name} analysis requires the ACET Engine Pack.\nMissing: {', '.join(gate['missing_required'])}.")
        install = box.addButton("Install Engine Pack", QMessageBox.ButtonRole.AcceptRole)
        fast = box.addButton("Use FAST instead", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        (ask or MODAL_EXEC)(box)
        clicked = box.clickedButton()
        if clicked is install:
            open_manager()
        elif clicked is fast:
            run("FAST@1")

    ctx.run(em.profile_gate, profile, no_ws=True, done=decide)
