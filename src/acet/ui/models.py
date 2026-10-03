"""Table models: virtualized views over row dicts; sort/filter via QSortFilterProxyModel (ACC-030)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt

Index = Any  # QModelIndex | QPersistentModelIndex (PySide6 has no py.typed)


TEXT_KEYS = frozenset(
    {
        "left_name",
        "right_name",
        "name",
        "label",
        "notes",
        "summary",
        "channel",
        "vendor",
        "error_code",
        "stage",
        "detail",
        "families",
        "release",
        "event_type",
        "source_class",
        "status",
        "deleted_at",
        "finished_at",
        "version_label",
        "source_label",
        "relations",
    }
)


def to_local(value: str) -> str:
    """Persisted UTC (…Z) → local display with offset (ACET-TIME-002, ACC-122). Dates stay as given."""
    from datetime import datetime

    if len(value) <= 10 or not value.endswith("Z"):
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


class RowsModel(QAbstractTableModel):
    def __init__(self, columns: Sequence[tuple[str, str]], parent: Any = None) -> None:
        super().__init__(parent)
        self.columns = list(columns)  # (key, header)
        self.rows: list[dict[str, Any]] = []

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        key = self.columns[index.column()][0]
        value = row.get(key)
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            if value is None:
                return "" if key in TEXT_KEYS else "UNKNOWN"  # never 0 (ACET-CHG-001, ACC-017)
            if isinstance(value, str) and key.endswith("_at"):
                return to_local(value)
            if isinstance(value, float):
                return f"{value:.4g}"
            if isinstance(value, int) and key.endswith("address"):
                return hex(value)
            return str(value)
        if role == Qt.ItemDataRole.UserRole:
            return value
        if role == Qt.ItemDataRole.ToolTipRole:
            return None if value is None else str(value)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section][1]
        return None

    def row_at(self, r: int) -> dict[str, Any]:
        return self.rows[r]


class FilterProxy(QSortFilterProxyModel):
    """Case-insensitive text filter across all columns + optional exact column filter."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setFilterKeyColumn(-1)
        self.setSortRole(Qt.ItemDataRole.UserRole)
        self.column_equals: tuple[int, str] | None = None

    def set_column_equals(self, column: int | None, value: str | None) -> None:
        if hasattr(self, "beginFilterChange"):  # Qt >= 6.10
            self.beginFilterChange()
            self.column_equals = None if column is None or not value else (column, value)
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            self.column_equals = None if column is None or not value else (column, value)
            self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:
        if self.column_equals is not None:
            col, val = self.column_equals
            idx = self.sourceModel().index(source_row, col, source_parent)
            if str(self.sourceModel().data(idx)) != val:
                return False
        return super().filterAcceptsRow(source_row, source_parent)

    def lessThan(self, left: Index, right: Index) -> bool:
        a, b = left.data(Qt.ItemDataRole.UserRole), right.data(Qt.ItemDataRole.UserRole)
        if a is None or b is None:
            return (a is None) and (b is not None)
        try:
            return bool(a < b)
        except TypeError:
            return str(a) < str(b)
