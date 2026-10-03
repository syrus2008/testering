"""Import wizard (spec §32) and first-launch wizard (spec §29). Keyboard-operable (ACC-044)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from acet.ui.widgets import Table


class ImportWizard(QWizard):
    PAGE_SOURCE, PAGE_META, PAGE_DETECT, PAGE_DUP, PAGE_ACTION, PAGE_SUMMARY = range(6)

    def __init__(self, ctx: Any) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle("Import build")
        self.preview: dict[str, Any] | None = None
        self.result: Any = None
        # Source
        src = QWizardPage()
        src.setTitle("Source")
        src.setSubTitle("Files or a folder on this machine. Nothing is fetched remotely and nothing is executed.")
        self.path = QLineEdit()
        self.path.setAccessibleName("Source path")
        b1, b2 = QPushButton("&Folder…"), QPushButton("F&iles…")
        b1.clicked.connect(
            lambda: self.path.setText(QFileDialog.getExistingDirectory(self, "Folder") or self.path.text())
        )
        b2.clicked.connect(
            lambda: self.path.setText(";".join(QFileDialog.getOpenFileNames(self, "Files")[0]) or self.path.text())
        )
        lay = QVBoxLayout(src)
        lay.addWidget(QLabel("&Path (use ; to separate several files):", buddy=self.path))
        lay.addWidget(self.path)
        row = QHBoxLayout()
        row.addWidget(b1)
        row.addWidget(b2)
        row.addStretch()
        lay.addLayout(row)
        src.registerField("path*", self.path)
        # Metadata
        meta = QWizardPage()
        meta.setTitle("Metadata")
        self.product = QComboBox()
        self.release, self.channel, self.observed, self.source_label = (
            QLineEdit(),
            QLineEdit(),
            QLineEdit(),
            QLineEdit(),
        )
        self.observed.setPlaceholderText("YYYY-MM-DD or ISO-8601 with timezone (optional)")
        form = QFormLayout(meta)
        for label, w in (
            ("&Product:", self.product),
            ("&Release label:", self.release),
            ("&Channel:", self.channel),
            ("&Observed at:", self.observed),
            ("&Source label:", self.source_label),
        ):
            w.setAccessibleName(label.replace("&", "").rstrip(":"))
            form.addRow(label, w)
        # Detection
        det = QWizardPage()
        det.setTitle("Detection")
        det.setSubTitle("Static format detection and proposed roles with a confidence class.")
        self.files = Table(
            [
                ("name", "File"),
                ("role", "Proposed role"),
                ("role_confidence", "Confidence"),
                ("format", "Format"),
                ("size_bytes", "Size"),
                ("existing_artifact", "Already stored"),
            ],
            "Detected files",
        )
        QVBoxLayout(det).addWidget(self.files)
        # Duplicates + storage
        dup = QWizardPage()
        dup.setTitle("Duplicates and storage")
        self.dup_text = QLabel("…")
        self.dup_text.setWordWrap(True)
        self.policy_add = QRadioButton("&Add an observation to the existing build")
        self.policy_cancel = QRadioButton("&Cancel (do not import)")
        self.policy_cancel.setChecked(True)
        dl = QVBoxLayout(dup)
        dl.addWidget(self.dup_text)
        dl.addWidget(self.policy_add)
        dl.addWidget(self.policy_cancel)
        # Action
        act = QWizardPage()
        act.setTitle("Action")
        self.actions = QButtonGroup(self)
        al = QVBoxLayout(act)
        for i, (label, prof) in enumerate(
            (
                ("Import &only", None),
                ("Import + &FAST", "FAST@1"),
                ("Import + &STANDARD", "STANDARD@1"),
                ("Import + &DEEP", "DEEP@1"),
            )
        ):
            rb = QRadioButton(label)
            rb.setProperty("profile", prof)
            self.actions.addButton(rb, i)
            al.addWidget(rb)
            if i == 1:
                rb.setChecked(True)
        # Summary
        summ = QWizardPage()
        summ.setTitle("Summary")
        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setAccessibleName("Import summary")
        QVBoxLayout(summ).addWidget(self.summary)
        for page_id, page in enumerate((src, meta, det, dup, act, summ)):
            self.setPage(page_id, page)
        self.currentIdChanged.connect(self._entered)
        ctx.load_products(self._fill_products)

    def _fill_products(self, rows: list[dict[str, Any]]) -> None:
        self.product.clear()
        for p in rows:
            self.product.addItem(p["name"], p["id"])

    def paths(self) -> list[Path]:
        return [Path(p) for p in self.path.text().split(";") if p.strip()]

    def _entered(self, page_id: int) -> None:
        if page_id == self.PAGE_DETECT:
            from acet.ingest.importer import preview_import

            self.files.set_rows([])

            def show(pv: dict[str, Any]) -> None:
                self.preview = pv
                self.files.set_rows(pv["files"])

            self.ctx.run(preview_import, self.paths(), self.product.currentData() or "", done=show)
        elif page_id == self.PAGE_DUP and self.preview is not None:
            pv = self.preview
            lines = [
                f"Build fingerprint: {pv['fingerprint'][:24]}…",
                f"New bytes to store: {pv['new_bytes']} (free: {pv['free_bytes']})",
            ]
            if pv["existing_build"]:
                lines.append(
                    f"An identical build already exists ({pv['existing_build'][:8]}). It will not be "
                    "duplicated: add an observation, or cancel."
                )
            else:
                lines.append("No identical build exists.")
            if pv["near_duplicates"]:
                lines.append(f"Warning: near-duplicate of {len(pv['near_duplicates'])} build(s) (never merged).")
            self.dup_text.setText("\n".join(lines))
            exists = bool(pv["existing_build"])
            self.policy_add.setEnabled(exists)
            self.policy_cancel.setEnabled(exists)
        elif page_id == self.PAGE_SUMMARY:
            self._run_import()

    def _run_import(self) -> None:
        from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build

        req = ImportRequest(
            self.paths(),
            self.product.currentData() or "",
            release_label=self.release.text() or None,
            channel=self.channel.text() or None,
            observed_at=self.observed.text() or None,
            source_label=self.source_label.text() or None,
            on_duplicate=DuplicatePolicy.ADD_OBSERVATION if self.policy_add.isChecked() else DuplicatePolicy.CANCEL,
        )
        profile = self.actions.checkedButton().property("profile")
        self.summary.setPlainText("Importing…")

        def done(res: Any) -> None:
            self.result = res
            self.summary.setPlainText(json.dumps(res.to_dict(), indent=2))
            if profile:
                from acet.analysis.orchestrator import analyze_build

                self.summary.appendPlainText(f"\nAnalysis {profile} started in the background (see Jobs).")
                self.ctx.run(
                    analyze_build,
                    res.build_id,
                    profile,
                    read_only=False,
                    done=lambda s: self.ctx.status(f"Analysis {s.status}"),
                )
            self.ctx.refresh_current()

        self.ctx.run(
            import_build,
            req,
            read_only=False,
            done=done,
            error=lambda e: self.summary.setPlainText(
                f"{e.code}: {e.spec.summary}\n{e.detail or ''}\nAction: {e.spec.action}"
            ),
        )


class FirstRunWizard(QWizard):
    """Welcome → Workspace → System scan → Engine Pack → Self-test → Finish."""

    def __init__(self, ctx: Any) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle("Welcome to ACET")
        self.created: Path | None = None
        welcome = QWizardPage()
        welcome.setTitle("Welcome")
        wl = QVBoxLayout(welcome)
        wl.addWidget(
            QLabel(
                "ACET compares binary components across versions. It never executes the files you import.\n"
                "Create a workspace (or open one from the File menu later)."
            )
        )
        ws_page = QWizardPage()
        ws_page.setTitle("Workspace")
        self.name = QLineEdit("My workspace")
        self.location = QLineEdit()
        from acet.platform.paths import workspaces_root

        self.location.setText(str(workspaces_root()))
        f = QFormLayout(ws_page)
        f.addRow("&Name:", self.name)
        f.addRow("&Location:", self.location)
        scan = QWizardPage()
        scan.setTitle("System scan")
        self.scan = Table([("name", "Check"), ("status", "Status"), ("detail", "Detail")], "System scan")
        QVBoxLayout(scan).addWidget(self.scan)
        engines = QWizardPage()
        engines.setTitle("Engine Pack")
        self.engines = QLabel("Detecting engines…")
        self.engines.setWordWrap(True)
        QVBoxLayout(engines).addWidget(self.engines)
        test = QWizardPage()
        test.setTitle("Self-test")
        self.test = QPlainTextEdit()
        self.test.setReadOnly(True)
        QVBoxLayout(test).addWidget(self.test)
        finish = QWizardPage()
        finish.setTitle("Finish")
        QVBoxLayout(finish).addWidget(QLabel("The dashboard opens next. Press Ctrl+K anytime to search."))
        for i, p in enumerate((welcome, ws_page, scan, engines, test, finish)):
            self.setPage(i, p)
        self.currentIdChanged.connect(self._entered)

    def _entered(self, i: int) -> None:
        if i == 2:
            from acet.platform.doctor import system_checks

            self.ctx.run(lambda: [c.to_dict() for c in system_checks()], no_ws=True, done=self.scan.set_rows)
            if self.created is None:
                from acet.application.workspace import create_workspace

                ws = create_workspace(self.name.text() or "workspace", Path(self.location.text()))
                self.created = ws.path
                ws.close()
        elif i == 3:
            from acet.engines.environment import detect

            def show(env: Any) -> None:
                lines = [
                    f"{k}: {'available' if v.available else 'not available'}"
                    f"{' (' + (v.version or '') + ')' if v.available else ' — ' + (v.reason or '')}"
                    for k, v in env.providers.items()
                    if k != "acet"
                ]
                self.engines.setText(
                    "\n".join(lines) + "\n\nWithout Ghidra, FAST analysis is available (DEGRADED). "
                    "Install the official Engine Pack for STANDARD/DEEP."
                )

            self.ctx.run(detect, no_ws=True, done=show)
        elif i == 4:
            from acet.platform.selftest import run_self_test

            self.test.setPlainText("Running the demo self-test…")
            self.ctx.run(run_self_test, no_ws=True, done=lambda r: self.test.setPlainText(json.dumps(r, indent=2)))
