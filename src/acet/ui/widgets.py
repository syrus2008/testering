"""Shared widgets: accessible tables, error dialog, state badge (no info carried by colour only, §51)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from acet.domain.error_codes import AcetError
from acet.ui.models import FilterProxy, RowsModel

STATE_TEXT = {
    "PARTIAL": "PARTIAL — some evidence is missing; see Missing evidence",
    "COMPLETED_PARTIAL": "PARTIAL — some evidence is missing; see Missing evidence",
    "STALE": "STALE — an upstream result changed; recompute to refresh",
    "OUT_OF_DISTRIBUTION": "OUT OF DISTRIBUTION — no calibration covers this context",
    "DEGRADED": "DEGRADED — an optional capability is unavailable",
    "CORRUPTED": "CORRUPTED — restore or re-import the object",
    "UNVERIFIED": "UNVERIFIED ENGINE — detected but not validated",
}


class Table(QWidget):
    """Filterable, sortable, keyboard-navigable table (ACC-030/044)."""

    def __init__(self, columns: Sequence[tuple[str, str]], name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.model = RowsModel(columns, self)
        self.proxy = FilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.filter = QLineEdit(self)
        self.filter.setPlaceholderText("Filter…")
        self.filter.setAccessibleName(f"{name} filter")
        self.filter.textChanged.connect(self.proxy.set_text)
        self.view = QTableView(self)
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setAlternatingRowColors(True)
        self.view.setAccessibleName(name)
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.verticalHeader().setDefaultSectionSize(22)
        self.view.setTabKeyNavigation(False)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.filter)
        lay.addWidget(self.view)

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.model.set_rows(rows)

    def fit_columns(self, stretch: str) -> None:
        """For short tables: every column as wide as its content, the descriptive ``stretch`` column takes the
        remaining width and wraps, rows grow to show it: nothing is elided."""
        header = self.view.horizontalHeader()
        header.setStretchLastSection(False)
        for i, (key, _title) in enumerate(self.model.columns):
            mode = QHeaderView.ResizeMode.Stretch if key == stretch else QHeaderView.ResizeMode.ResizeToContents
            header.setSectionResizeMode(i, mode)
        self.view.setWordWrap(True)
        self.view.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

    def selected(self) -> dict[str, Any] | None:
        idx = self.view.currentIndex()
        if not idx.isValid():
            return None
        return self.model.row_at(self.proxy.mapToSource(idx).row())


def badge(text: str) -> QLabel:
    lab = QLabel(STATE_TEXT.get(text, text))
    lab.setAccessibleName(f"state: {text}")
    lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lab


class ErrorDialog(QDialog):
    """Summary, data impact, recommended action, diagnostics, stable code; stack trace hidden (§54)."""

    def __init__(self, err: AcetError, details: str, parent: QWidget | None = None, on_diagnostics: Any = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{err.code}: {err.spec.summary}")
        lay = QVBoxLayout(self)
        for label, text in (
            ("Code", err.code),
            ("Summary", err.spec.summary + (f" — {err.detail}" if err.detail else "")),
            ("Impact on your data", err.spec.impact),
            ("Recommended action", err.spec.action),
        ):
            line = QLabel(f"<b>{label}:</b> {text}")
            line.setWordWrap(True)
            line.setTextFormat(Qt.TextFormat.RichText)
            lay.addWidget(line)
        if err.data:
            lay.addWidget(QLabel(json.dumps(err.data, ensure_ascii=False)[:500]))
        self.dev = QPlainTextEdit(details)
        self.dev.setReadOnly(True)
        self.dev.setVisible(False)
        self.dev.setAccessibleName("Developer details")
        toggle = QPushButton("Developer details")
        toggle.setCheckable(True)
        toggle.toggled.connect(self.dev.setVisible)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        row = QHBoxLayout()
        diag = QPushButton("Create diagnostic package…")
        diag.setEnabled(on_diagnostics is not None)
        if on_diagnostics is not None:
            diag.clicked.connect(on_diagnostics)
        row.addWidget(diag)
        row.addWidget(toggle)
        row.addStretch()
        row.addWidget(buttons)
        lay.addLayout(row)
        lay.addWidget(self.dev)


def info(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


class PartialBanner(QLabel):
    """Very visible notice for a COMPLETED_PARTIAL run: what is missing, and that missing evidence is not
    negative evidence. Text comes from acet.reporting.vocabulary.completeness (same as reports)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWordWrap(True)
        self.setAccessibleName("Completeness warning")
        self.setStyleSheet(
            "QLabel{border:3px solid #b45309;background:#fff7ed;color:#7c2d12;padding:8px;font-weight:600}"
        )
        self.setVisible(False)

    def show_completeness(self, c: dict[str, Any]) -> None:
        if not c.get("is_partial"):
            self.setVisible(False)
            self.setText("")
            return
        missing = "\n".join(
            f"• Missing: {m['processor']} — {m.get('outcome')}: {m.get('reason')}" for m in c["missing"]
        )
        self.setText(
            f"⚠ {c['title']}\nRun status: {c['run_status']}\n{missing}\n{c['statement']}".replace("\n\n", "\n")
        )
        self.setVisible(True)
