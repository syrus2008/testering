"""UI pages (spec §30–38). Every data load and action goes through the background TaskRunner."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFont, QKeySequence, QPainter, QShortcut
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGraphicsScene,
    QGraphicsView,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from acet.ui.widgets import Table, badge


class Page(QWidget):
    title = "Page"

    def __init__(self, ctx: Any) -> None:
        super().__init__()
        self.ctx = ctx
        self.setAccessibleName(self.title)

    def refresh(self) -> None:  # called when the page is shown
        return None

    def after(self, message: Callable[[Any], str], then: Callable[[], None]) -> Callable[[Any], None]:
        """Callback: show a status message built from the result, then refresh something."""

        def cb(result: Any) -> None:
            self.ctx.status(message(result))
            then()

        return cb

    def bg(
        self, fn: Callable[..., Any], *args: Any, done: Callable[[Any], None] | None = None, read_only: bool = True
    ) -> None:
        self.ctx.run(fn, *args, done=done, read_only=read_only)

    def button(self, text: str, slot: Callable[[], None], shortcut: str | None = None) -> QPushButton:
        b = QPushButton(text)
        b.setAccessibleName(text.replace("&", ""))
        b.clicked.connect(slot)
        if shortcut:
            b.setShortcut(QKeySequence(shortcut))
        return b


# ----------------------------------------------------------------- dashboard
class DashboardPage(Page):
    title = "Dashboard"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        self.storage = QLabel("Storage: …")
        self.storage.setAccessibleName("Storage")
        self.products = Table([("name", "Product"), ("builds", "Builds"), ("vendor", "Vendor")], "Products")
        self.builds = Table(
            [
                ("version_label", "Release"),
                ("status", "Status"),
                ("observations", "Observations"),
                ("first_observed", "First observed"),
                ("id", "Build id"),
            ],
            "Recent builds",
        )
        self.jobs = Table(
            [("job_type", "Job"), ("state", "State"), ("stage", "Stage"), ("progress", "Progress")], "Active jobs"
        )
        self.changes = Table(
            [
                ("component_role", "Component"),
                ("dimension", "Dimension"),
                ("severity_class", "Severity"),
                ("reliability_class", "Reliability"),
                ("analysis_run_id", "Run"),
            ],
            "Recent significant changes",
        )
        row = QHBoxLayout()
        row.addWidget(self.button("System &health (Doctor)", lambda: ctx.goto("System")))
        row.addWidget(self.button("&Import build…", ctx.open_import_wizard))
        row.addWidget(self.button("Change &explorer", lambda: ctx.goto("Changes")))
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(self.storage)
        grid = QSplitter(Qt.Orientation.Vertical)
        for title, w in (
            ("Products", self.products),
            ("Recent builds", self.builds),
            ("Active jobs", self.jobs),
            ("Recent significant changes (UNUSUAL / EXTREME, per dimension)", self.changes),
        ):
            box = QGroupBox(title)
            QVBoxLayout(box).addWidget(w)
            grid.addWidget(box)
        lay.addWidget(grid, 1)
        self.builds.view.doubleClicked.connect(lambda _i: ctx.open_build((self.builds.selected() or {}).get("id")))

    def refresh(self) -> None:
        from acet.application.views import dashboard

        def show(d: dict[str, Any]) -> None:
            s = d["storage"]
            self.storage.setText(
                f"Workspace “{s['workspace']}” — artifacts {s['artifact_bytes'] / 1e6:.1f} MB, "
                f"free disk {s['free_bytes'] / 1e9:.1f} GB"
            )
            self.products.set_rows(d["products"])
            self.builds.set_rows(d["recent_builds"])
            self.jobs.set_rows(d["active_jobs"])
            self.changes.set_rows(d["recent_changes"])

        self.bg(dashboard, done=show)


# ----------------------------------------------------------------- products
class ProductsPage(Page):
    title = "Products"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(self.button("&New product…", self.new_product))
        row.addWidget(self.button("&Add build…", ctx.open_import_wizard))
        row.addWidget(self.button("&Timeline", self.timeline))
        row.addWidget(self.button("&Lineage", lambda: ctx.goto("Lineage")))
        row.addStretch()
        lay.addLayout(row)
        self.table = Table(
            [("name", "Product"), ("vendor", "Vendor"), ("builds", "Builds"), ("created_at", "Created"), ("id", "Id")],
            "Products table",
        )
        lay.addWidget(self.table)

    def refresh(self) -> None:
        from acet.application.views import products

        self.bg(products, done=self.table.set_rows)

    def new_product(self) -> None:
        name, ok = QInputDialog.getText(self, "New product", "Product name:")
        if ok and name.strip():
            from acet.application.products import create_product

            self.ctx.run(create_product, name.strip(), done=lambda _p: self.refresh(), read_only=False)

    def timeline(self) -> None:
        sel = self.table.selected()
        if sel:
            self.ctx.pages["Timeline"].select_product(sel["id"])
            self.ctx.goto("Timeline")


# ----------------------------------------------------------------- builds
class BuildsPage(Page):
    title = "Builds"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(self.button("Analyze &FAST", lambda: self.analyze("FAST@1")))
        row.addWidget(self.button("Analyze &STANDARD", lambda: self.analyze("STANDARD@1")))
        row.addWidget(self.button("&Verify integrity", self.verify))
        row.addWidget(self.button("Move to &trash", self.trash))
        row.addStretch()
        lay.addLayout(row)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = Table(
            [
                ("version_label", "Release"),
                ("channel", "Channel"),
                ("status", "Completeness"),
                ("observations", "Observations"),
                ("first_observed", "First observed"),
                ("last_observed", "Last observed"),
                ("id", "Build id"),
            ],
            "Builds table",
        )
        self.table.view.selectionModel().currentRowChanged.connect(lambda *_: self.load_detail())
        split.addWidget(self.table)
        detail = QWidget()
        dl = QVBoxLayout(detail)
        self.banner = QLabel("Select a build")
        self.banner.setWordWrap(True)
        self.banner.setAccessibleName("Build banner")
        dl.addWidget(self.banner)
        self.tabs = QTabWidget()
        self.components = Table(
            [
                ("role", "Role"),
                ("role_confidence", "Confidence"),
                ("label", "File"),
                ("format", "Format"),
                ("size_bytes", "Size"),
                ("integrity_state", "Integrity"),
                ("sha256", "SHA-256"),
            ],
            "Components",
        )
        self.observations = Table(
            [
                ("observed_at", "Observed at"),
                ("time_precision", "Precision"),
                ("source_type", "Source"),
                ("source_label", "Label"),
                ("imported_at", "Imported"),
            ],
            "Observations",
        )
        self.runs = Table(
            [
                ("scope_type", "Scope"),
                ("status", "Status"),
                ("coverage", "Coverage"),
                ("started_at", "Started"),
                ("id", "Run id"),
            ],
            "Analysis runs",
        )
        for name, w in (
            ("Components", self.components),
            ("Observations", self.observations),
            ("Analysis runs", self.runs),
        ):
            self.tabs.addTab(w, name)
        dl.addWidget(self.tabs)
        split.addWidget(detail)
        lay.addWidget(split, 1)

    def refresh(self) -> None:
        from acet.application.views import builds

        self.bg(builds, done=self.table.set_rows)

    def select_build(self, build_id: str | None) -> None:
        if not build_id:
            return
        for r in range(self.table.proxy.rowCount()):
            src = self.table.proxy.mapToSource(self.table.proxy.index(r, 0))
            if self.table.model.row_at(src.row()).get("id") == build_id:
                self.table.view.selectRow(r)
                self.table.view.setFocus()
                return

    def load_detail(self) -> None:
        sel = self.table.selected()
        if not sel:
            return
        from acet.application.builds import get_build
        from acet.application.views import runs

        def show(b: dict[str, Any]) -> None:
            obs = [o["observed_at"] for o in b["observations"] if o["observed_at"]]
            rec = "STANDARD@1" if any(c["format"] in ("PE32", "PE32+") for c in b["components"]) else "FAST@1"
            self.banner.setText(
                f"Completeness: {b['status']} · fingerprint {b['build_fingerprint'][:16]}… · first observation "
                f"{min(obs) if obs else 'UNKNOWN'} · last {max(obs) if obs else 'UNKNOWN'} · recommended analysis {rec}"
            )
            self.components.set_rows(b["components"])
            self.observations.set_rows(b["observations"])

        self.bg(get_build, sel["id"], done=show)
        self.bg(runs, sel["id"], done=self.runs.set_rows)

    def analyze(self, profile: str) -> None:
        sel = self.table.selected()
        if not sel:
            return
        from acet.analysis.orchestrator import analyze_build

        self.ctx.status(f"Analysis {profile} started for build {sel['id'][:8]}…")
        self.ctx.run(
            analyze_build,
            sel["id"],
            profile,
            read_only=False,
            done=self.after(lambda s: f"Analysis {s.status} (coverage {s.coverage})", self.load_detail),
        )

    def verify(self) -> None:
        sel = self.table.selected()
        if sel:
            from acet.application.builds import verify_build_artifacts

            self.ctx.run(
                verify_build_artifacts,
                sel["id"],
                read_only=False,
                done=lambda shas: self.ctx.status(f"{len(shas)} artifact(s) verified"),
            )

    def trash(self) -> None:
        sel = self.table.selected()
        if (
            sel
            and QMessageBox.question(
                self, "Move to trash", "Move this build to the trash? It stays recoverable until an explicit purge."
            )
            == QMessageBox.StandardButton.Yes
        ):
            from acet.application.builds import soft_delete_build

            self.ctx.run(soft_delete_build, sel["id"], read_only=False, done=lambda _x: self.refresh())


# ----------------------------------------------------------------- compare
class ComparePage(Page):
    title = "Compare"
    DECISIONS = ("", "EXACT", "STRONG", "PROBABLE", "AMBIGUOUS", "CONFLICT", "UNRESOLVED")

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        form = QHBoxLayout()
        self.left, self.right, self.profile = QComboBox(), QComboBox(), QComboBox()
        for w, n in ((self.left, "Left build"), (self.right, "Right build"), (self.profile, "Profile")):
            w.setAccessibleName(n)
        self.profile.addItems(["STANDARD@1", "STANDARD@2", "DEEP@1", "DEEP@2", "RESEARCH@1"])
        for lbl, w in (("&Left", self.left), ("&Right", self.right), ("&Profile", self.profile)):
            q = QLabel(lbl)
            q.setBuddy(w)
            form.addWidget(q)
            form.addWidget(w, 1)
        form.addWidget(self.button("&Compare", self.compare, "Ctrl+Return"))
        lay.addLayout(form)
        row = QHBoxLayout()
        self.runs = QComboBox()
        self.runs.setAccessibleName("Compare run")
        self.runs.currentIndexChanged.connect(lambda _i: self.load_run())
        self.decision = QComboBox()
        self.decision.addItems(list(self.DECISIONS))
        self.decision.setAccessibleName("Decision filter")
        row.addWidget(QLabel("Run:"))
        row.addWidget(self.runs, 2)
        row.addWidget(QLabel("Decision:"))
        row.addWidget(self.decision)
        row.addWidget(self.button("Detect &changes", self.detect))
        row.addWidget(self.button("E&xport report…", self.export))
        lay.addLayout(row)
        self.state = QLabel("")
        lay.addWidget(self.state)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.functions = Table(
            [
                ("component", "Component"),
                ("left_name", "Left"),
                ("left_address", "Left addr"),
                ("right_name", "Right"),
                ("right_address", "Right addr"),
                ("decision", "Decision"),
                ("strength_class", "Strength"),
                ("evidence_diversity", "Evidence families"),
                ("engine_count", "Engines"),
                ("families", "Supporting families"),
            ],
            "Function table",
        )
        self.decision.currentTextChanged.connect(lambda t: self.functions.proxy.set_column_equals(5, t))
        self.functions.view.selectionModel().currentRowChanged.connect(lambda *_: self.inspect())
        self.inspector = QPlainTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setAccessibleName("Evidence inspector")
        split.addWidget(self.functions)
        split.addWidget(self.inspector)
        split.setSizes([700, 400])
        lay.addWidget(split, 1)

    def refresh(self) -> None:
        from acet.application.views import builds, runs

        def fill(rows: list[dict[str, Any]]) -> None:
            for combo in (self.left, self.right):
                cur = combo.currentData()
                combo.clear()
                for b in rows:
                    combo.addItem(f"{b['version_label'] or b['id'][:8]} ({b['status']})", b["id"])
                if cur:
                    combo.setCurrentIndex(max(0, combo.findData(cur)))
            if self.right.count() > 1 and self.right.currentIndex() == 0:
                self.right.setCurrentIndex(1)

        def fill_runs(rows: list[dict[str, Any]]) -> None:
            cur = self.runs.currentData()
            self.runs.blockSignals(True)
            self.runs.clear()
            for r in rows:
                if r["scope_type"] == "compare":
                    self.runs.addItem(f"{r['started_at'][:19]} {r['status']} cov={r['coverage']}", r["id"])
            self.runs.blockSignals(False)
            if self.runs.count():
                self.runs.setCurrentIndex(max(0, self.runs.findData(cur)))
                self.load_run()

        self.bg(builds, done=fill)
        self.bg(runs, done=fill_runs)

    def compare(self) -> None:
        left, right = self.left.currentData(), self.right.currentData()
        if not left or not right or left == right:
            self.ctx.status("Choose two different builds")
            return
        from acet.analysis.orchestrator import compare_builds

        self.ctx.status(f"Comparison {self.profile.currentText()} running in background…")
        self.ctx.run(
            compare_builds,
            left,
            right,
            self.profile.currentText(),
            read_only=False,
            done=self.after(lambda s: f"Comparison {s.status}", self.refresh),
        )

    def load_run(self) -> None:
        run = self.runs.currentData()
        if not run:
            return
        from acet.application.views import functions_for_run

        def show(rows: list[dict[str, Any]]) -> None:
            self.functions.set_rows(rows)
            self.state.setText(
                "Confidence shown as classes (no probability without validated calibration). "
                "UNRESOLVED ≠ new or removed."
            )

        self.bg(functions_for_run, run, done=show)

    def inspect(self) -> None:
        sel = self.functions.selected()
        if sel:
            from acet.application.views import evidence

            self.bg(evidence, sel["id"], done=lambda d: self.inspector.setPlainText(json.dumps(d, indent=2)))

    def detect(self) -> None:
        run = self.runs.currentData()
        if run:
            from acet.changes.detector import detect_changes

            def done(_r: Any) -> None:
                self.ctx.pages["Changes"].select_run(run)
                self.ctx.goto("Changes")

            self.ctx.run(detect_changes, run, read_only=False, done=done)

    def export(self) -> None:
        run = self.runs.currentData()
        if run:
            self.ctx.pages["Reports"].select_run(run)
            self.ctx.goto("Reports")


# ----------------------------------------------------------------- timeline
class TimelinePage(Page):
    title = "Timeline"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.product = QComboBox()
        self.product.setAccessibleName("Product")
        self.product.currentIndexChanged.connect(lambda _i: self.load())
        row.addWidget(QLabel("Product:"))
        row.addWidget(self.product, 1)
        row.addWidget(self.button("Add external &event…", self.add_event))
        lay.addLayout(row)
        lay.addWidget(QLabel("External events are context: proximity is a temporal correlation, never a cause."))
        self.table = Table(
            [
                ("at", "When"),
                ("kind", "Kind"),
                ("release", "Release"),
                ("event_type", "Event"),
                ("summary", "Summary"),
                ("source_class", "Source class"),
                ("status", "Status"),
            ],
            "Timeline",
        )
        lay.addWidget(self.table)
        self._pending: str | None = None

    def select_product(self, pid: str) -> None:
        self._pending = pid

    def refresh(self) -> None:
        from acet.application.views import products

        def fill(rows: list[dict[str, Any]]) -> None:
            self.product.blockSignals(True)
            self.product.clear()
            for p in rows:
                self.product.addItem(p["name"], p["id"])
            self.product.blockSignals(False)
            if self._pending:
                self.product.setCurrentIndex(max(0, self.product.findData(self._pending)))
            self.load()

        self.bg(products, done=fill)

    def load(self) -> None:
        pid = self.product.currentData()
        if pid:
            from acet.changes.timeline import product_timeline

            self.bg(product_timeline, pid, done=self.table.set_rows)

    def add_event(self) -> None:
        pid = self.product.currentData()
        if not pid:
            return
        summary, ok = QInputDialog.getText(self, "External event", "Summary:")
        if not ok or not summary:
            return
        sc, ok = QInputDialog.getItem(
            self, "External event", "Source class:", ["OFFICIAL", "RESEARCH", "COMMUNITY", "LOCAL_NOTE"], 3, False
        )
        if not ok:
            return
        when, _ = QInputDialog.getText(self, "External event", "Date (YYYY-MM-DD, optional):")
        from acet.changes.events import add_event

        self.ctx.run(
            add_event,
            pid,
            read_only=False,
            done=lambda _x: self.load(),
            kwargs={"event_type": "note", "summary": summary, "source_class": sc, "occurred_at": when or None},
        )


# ----------------------------------------------------------------- lineage
class LineageGraph(QGraphicsView):
    """Versioned graph: one column per build, one node per instance; keyboard zoom (+/-)."""

    def __init__(self) -> None:
        super().__init__()
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setAccessibleName("Lineage graph")
        QShortcut(QKeySequence("+"), self, activated=lambda: self.scale(1.2, 1.2))
        QShortcut(QKeySequence("-"), self, activated=lambda: self.scale(1 / 1.2, 1 / 1.2))

    def show_history(self, rows: list[dict[str, Any]]) -> None:
        sc = self.scene()
        sc.clear()
        builds: list[str] = []
        for r in rows:
            if r["build_id"] not in builds:
                builds.append(r["build_id"])
        prev = None
        for r in rows:
            x = builds.index(r["build_id"]) * 220
            y = 20
            node = sc.addRect(x, y, 180, 46, brush=QBrush(QColor("#e8eef7")))
            node.setToolTip(f"{r['relation']} {r['name'] or hex(r['address'])}")
            t = sc.addText(f"{r['relation']}\n{r['name'] or hex(r['address'])}")
            t.setPos(x + 4, y + 2)
            t.setFont(QFont("", 8))
            if prev is not None and r["relation"] != "DISAPPEARED":
                sc.addLine(prev + 180, y + 23, x, y + 23)
            prev = x


class LineagePage(Page):
    title = "Lineage"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.product = QComboBox()
        self.product.setAccessibleName("Product")
        self.product.currentIndexChanged.connect(lambda _i: self.load())
        row.addWidget(QLabel("Product:"))
        row.addWidget(self.product, 1)
        row.addWidget(self.button("&Build / extend lineage", self.build))
        lay.addLayout(row)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = Table(
            [
                ("label", "Function"),
                ("component_role", "Component"),
                ("instances", "Instances"),
                ("relations", "Relations (split/merge/conflicts)"),
                ("id", "Lineage id"),
            ],
            "Lineages",
        )
        self.table.view.selectionModel().currentRowChanged.connect(lambda *_: self.history())
        self.hist = Table(
            [
                ("build_id", "Build"),
                ("relation", "Relation"),
                ("name", "Name"),
                ("address", "Address"),
                ("status", "Status"),
            ],
            "Lineage history",
        )
        self.graph = LineageGraph()
        split.addWidget(self.table)
        split.addWidget(self.hist)
        split.addWidget(self.graph)
        lay.addWidget(split, 1)

    def refresh(self) -> None:
        from acet.application.views import products

        def fill(rows: list[dict[str, Any]]) -> None:
            cur = self.product.currentData()
            self.product.blockSignals(True)
            self.product.clear()
            for p in rows:
                self.product.addItem(p["name"], p["id"])
            self.product.blockSignals(False)
            if cur:
                self.product.setCurrentIndex(max(0, self.product.findData(cur)))
            self.load()

        self.bg(products, done=fill)

    def load(self) -> None:
        pid = self.product.currentData()
        if pid:
            from acet.application.views import lineages

            self.bg(lineages, pid, done=self.table.set_rows)

    def build(self) -> None:
        pid = self.product.currentData()
        if pid:
            from acet.lineage.builder import build_lineage

            self.ctx.run(
                build_lineage,
                pid,
                read_only=False,
                done=self.after(lambda s: f"Lineage: {s.lineages} lineages, carried {s.carried_forward}", self.load),
            )

    def history(self) -> None:
        sel = self.table.selected()
        if sel:
            from acet.lineage.builder import lineage_history

            def show(rows: list[dict[str, Any]]) -> None:
                self.hist.set_rows(rows)
                self.graph.show_history(rows)

            self.bg(lineage_history, sel["id"], done=show)


# ----------------------------------------------------------------- changes
class ChangesPage(Page):
    title = "Changes"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        self.run = QComboBox()
        self.run.setAccessibleName("Compare run")
        self.run.currentIndexChanged.connect(lambda _i: self.load())
        row = QHBoxLayout()
        row.addWidget(QLabel("Run:"))
        row.addWidget(self.run, 1)
        lay.addLayout(row)
        lay.addWidget(
            QLabel(
                "Each dimension is reported separately with its measurement state, severity (baseline) and "
                "reliability. ACET computes no global score; UNKNOWN is never 0."
            )
        )
        self.table = Table(
            [
                ("component", "Component"),
                ("dimension", "Dimension"),
                ("state", "Measurement"),
                ("severity", "Severity"),
                ("reliability", "Reliability"),
                ("summary", "Metrics"),
                ("notes", "Notes"),
            ],
            "Detected changes",
        )
        lay.addWidget(self.table)
        self._pending: str | None = None

    def select_run(self, run_id: str) -> None:
        self._pending = run_id

    def refresh(self) -> None:
        from acet.application.views import runs

        def fill(rows: list[dict[str, Any]]) -> None:
            self.run.blockSignals(True)
            self.run.clear()
            for r in rows:
                if r["scope_type"] == "compare":
                    self.run.addItem(f"{r['started_at'][:19]} {r['status']}", r["id"])
            self.run.blockSignals(False)
            if self._pending:
                self.run.setCurrentIndex(max(0, self.run.findData(self._pending)))
            self.load()

        self.bg(runs, done=fill)

    def load(self) -> None:
        run = self.run.currentData()
        if run:
            from acet.application.views import changes

            self.bg(changes, run, done=self.table.set_rows)


# ----------------------------------------------------------------- benchmarks
class BenchmarksPage(Page):
    title = "Benchmarks"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.path = QLineEdit()
        self.path.setAccessibleName("Dataset directory")
        self.profile = QComboBox()
        self.profile.addItems(["STANDARD@1", "DEEP@1", "STANDARD@2"])
        self.split = QComboBox()
        self.split.addItems(["all", "calibration", "test"])
        form.addRow("&Dataset directory:", self.path)
        form.addRow("&Profile:", self.profile)
        form.addRow("&Split:", self.split)
        lay.addLayout(form)
        row = QHBoxLayout()
        row.addWidget(self.button("&Browse…", self.browse))
        row.addWidget(self.button("&Run benchmark", self.run))
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(
            QLabel(
                "Ground truth is read only by the evaluator (blind evaluation). Calibrated probabilities "
                "appear only for validated, matching contexts; otherwise classes / OUT_OF_DISTRIBUTION."
            )
        )
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setAccessibleName("Benchmark results")
        lay.addWidget(self.out)
        from acet.platform.selftest import demo_dataset

        demo = demo_dataset()
        if demo:
            self.path.setText(str(demo))

    def browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Dataset directory")
        if d:
            self.path.setText(d)

    def run(self) -> None:
        from acet.benchmark.runner import run_benchmark

        self.out.setPlainText("Running…")
        self.ctx.run(
            run_benchmark,
            Path(self.path.text()),
            self.profile.currentText(),
            read_only=False,
            kwargs={"split": self.split.currentText()},
            done=lambda r: self.out.setPlainText(
                json.dumps({"summary": r["summary"], "manifest": r["manifest"]}, indent=2)
            ),
        )


# ----------------------------------------------------------------- reports
class ReportsPage(Page):
    title = "Reports"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.run = QComboBox()
        self.fmt = QComboBox()
        self.fmt.addItems(["html", "md", "json", "csv"])
        form.addRow("&Run:", self.run)
        form.addRow("&Format:", self.fmt)
        lay.addLayout(form)
        row = QHBoxLayout()
        row.addWidget(self.button("&Export report…", self.export))
        row.addWidget(self.button("Export .&acetpack…", self.pack))
        row.addStretch()
        lay.addLayout(row)
        self.out = QLabel("")
        self.out.setWordWrap(True)
        lay.addWidget(self.out)
        lay.addStretch()
        self._pending: str | None = None

    def select_run(self, run_id: str) -> None:
        self._pending = run_id

    def refresh(self) -> None:
        from acet.application.views import runs

        def fill(rows: list[dict[str, Any]]) -> None:
            self.run.clear()
            for r in rows:
                if r["scope_type"] == "compare":
                    self.run.addItem(f"{r['started_at'][:19]} {r['status']}", r["id"])
            if self._pending:
                self.run.setCurrentIndex(max(0, self.run.findData(self._pending)))

        self.bg(runs, done=fill)

    def export(self) -> None:
        run = self.run.currentData()
        if not run:
            return
        fmt = self.fmt.currentText()
        dest, _ = QFileDialog.getSaveFileName(self, "Export report", f"acet-report.{fmt}")
        if not dest:
            return
        from acet.reporting.model import compare_report
        from acet.reporting.render import write_report

        def make(ws: Any, run_id: str) -> str:
            return str(write_report(compare_report(ws, run_id), fmt, Path(dest)))

        self.ctx.run(make, run, done=lambda p: self.out.setText(f"Report written: {p}"))

    def pack(self) -> None:
        dest, _ = QFileDialog.getSaveFileName(self, "Export .acetpack", "workspace.acetpack")
        if dest:
            from acet.reporting.acetpack import create_pack

            include = (
                QMessageBox.question(self, "Artifacts", "Include original artifact bytes? (opt-in)")
                == QMessageBox.StandardButton.Yes
            )
            self.ctx.run(
                create_pack,
                Path(dest),
                read_only=False,
                kwargs={"include_artifacts": include},
                done=lambda p: self.out.setText(f"Pack written: {p}"),
            )


# ----------------------------------------------------------------- jobs
class JobsPage(Page):
    title = "Jobs"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(self.button("&Pause", lambda: self.request("pause")))
        row.addWidget(self.button("&Resume", self.resume))
        row.addWidget(self.button("&Cancel", lambda: self.request("cancel")))
        row.addWidget(self.button("Re&fresh", self.refresh))
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(QLabel("Cancelling keeps finished, cache-compatible results. Interrupted jobs can be resumed."))
        self.table = Table(
            [
                ("job_type", "Job"),
                ("state", "State"),
                ("stage", "Stage"),
                ("progress", "Progress"),
                ("attempts", "Attempts"),
                ("error_code", "Error"),
                ("updated_at", "Updated"),
                ("id", "Job id"),
            ],
            "Jobs table",
        )
        lay.addWidget(self.table)
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(lambda: self.refresh() if self.isVisible() else None)
        self.timer.start()

    def refresh(self) -> None:
        from acet.application.views import jobs

        self.bg(jobs, done=self.table.set_rows)

    def request(self, what: str) -> None:
        sel = self.table.selected()
        if sel:
            from acet.jobs.store import request

            self.ctx.run(request, sel["id"], what, read_only=False, done=lambda _x: self.refresh(), ws_db=True)

    def resume(self) -> None:
        sel = self.table.selected()
        if sel:
            from acet.analysis.orchestrator import resume

            self.ctx.run(
                resume,
                sel["id"],
                read_only=False,
                done=self.after(lambda s: f"Resumed: {s.status}", self.refresh),
            )


# ----------------------------------------------------------------- system / doctor
class SystemPage(Page):
    title = "System"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(self.button("Run &Doctor", self.refresh))
        row.addWidget(self.button("Golden &self-test", self.selftest))
        row.addWidget(self.button("&Reconcile store", self.reconcile))
        row.addWidget(self.button("Cleanup (&dry run)", self.cleanup))
        row.addWidget(self.button("Diagnostic &package…", ctx.diagnostics))
        row.addStretch()
        lay.addLayout(row)
        self.health = badge("…")
        lay.addWidget(self.health)
        self.table = Table([("name", "Check"), ("status", "Status"), ("detail", "Detail")], "Doctor checks")
        lay.addWidget(self.table)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setAccessibleName("System output")
        lay.addWidget(self.out)

    def refresh(self) -> None:
        def doctor(ws: Any) -> dict[str, Any]:
            from acet.engines.quirks import load_known_limitations
            from acet.platform.doctor import overall_health, system_checks, workspace_checks

            checks = system_checks() + workspace_checks(ws)[0]
            return {
                "health": overall_health(checks).value,
                "checks": [c.to_dict() for c in checks],
                "limitations": [k.__dict__ for k in load_known_limitations()],
            }

        def show(d: dict[str, Any]) -> None:
            self.health.setText(f"System health: {d['health']}")
            self.table.set_rows(d["checks"])
            self.out.setPlainText(
                "Known limitations registry:\n"
                + "\n".join(
                    f"- {k['id']} [{k['provider_id']}] {k['symptom']} — {k['workaround']}" for k in d["limitations"]
                )
            )
            self.ctx.set_health(d["health"])

        self.bg(doctor, done=show)

    def selftest(self) -> None:
        from acet.platform.selftest import run_self_test

        self.out.setPlainText("Running golden self-test…")
        self.ctx.run(run_self_test, done=lambda r: self.out.setPlainText(json.dumps(r, indent=2)), no_ws=True)

    def reconcile(self) -> None:
        from acet.platform.doctor import reconcile

        self.bg(reconcile, done=lambda r: self.out.setPlainText(json.dumps(r.to_dict(), indent=2)))

    def cleanup(self) -> None:
        from acet.platform.retention import apply_cleanup, plan_cleanup

        def show(plan: Any) -> None:
            self.out.setPlainText(json.dumps(plan.to_dict(), indent=2))
            if (
                plan.items
                and QMessageBox.question(
                    self,
                    "Cleanup",
                    f"Delete {len(plan.items)} item(s), {plan.total_bytes} bytes? Sources and current "
                    "results are never touched.",
                )
                == QMessageBox.StandardButton.Yes
            ):
                self.ctx.run(
                    lambda ws: apply_cleanup(ws, plan_cleanup(ws)),
                    read_only=False,
                    done=lambda n: self.out.appendPlainText(f"\nfreed {n} bytes"),
                )

        self.bg(plan_cleanup, done=show)


# ----------------------------------------------------------------- settings
class SettingsPage(Page):
    title = "Settings"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        lay = QVBoxLayout(self)
        lay.addWidget(
            QLabel("Scientific parameters can only be changed in Research or Developer mode (safe defaults).")
        )
        self.table = Table([("key", "Setting"), ("value", "Value"), ("required_mode", "Mode required")], "Settings")
        lay.addWidget(self.table)
        lay.addWidget(self.button("&Edit selected…", self.edit))

    def refresh(self) -> None:
        def load(ws: Any) -> list[dict[str, Any]]:
            from acet.application.settings import SETTINGS, effective_settings

            return [
                {"key": k, "value": json.dumps(v), "required_mode": SETTINGS[k][1].value}
                for k, v in effective_settings(ws).items()
            ]

        self.bg(load, done=self.table.set_rows)

    def edit(self) -> None:
        sel = self.table.selected()
        if not sel:
            return
        text, ok = QInputDialog.getText(self, sel["key"], "Value (JSON):", text=sel["value"])
        if ok:
            from acet.application.settings import set_setting

            self.ctx.run(set_setting, sel["key"], json.loads(text), read_only=False, done=lambda _x: self.refresh())


PAGES = [
    DashboardPage,
    ProductsPage,
    BuildsPage,
    ComparePage,
    TimelinePage,
    LineagePage,
    ChangesPage,
    BenchmarksPage,
    ReportsPage,
    JobsPage,
    SystemPage,
    SettingsPage,
]
