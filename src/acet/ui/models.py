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


def display_text(key: str, value: Any) -> str:
    if value is None:
        return "" if key in TEXT_KEYS else "UNKNOWN"  # never 0 (ACET-CHG-001, ACC-017)
    if isinstance(value, str) and key.endswith("_at"):
        return to_local(value)
    if isinstance(value, float):
        return f"{value:.4g}"
    if isinstance(value, int) and key.endswith("address"):
        return hex(value)
    return str(value)


def _sort_key(value: Any) -> tuple[Any, ...]:
    # None first, then numbers, then everything else by text: a total order for mixed columns.
    if value is None:
        return (0,)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (1, value)
    return (2, str(value))


class RowsModel(QAbstractTableModel):
    """Rows are plain dicts. Display strings are computed once per row so that filtering and
    sorting 10 000+ rows run in Python's C loops, not in one Qt→Python call per cell (ACC-030)."""

    def __init__(self, columns: Sequence[tuple[str, str]], parent: Any = None) -> None:
        super().__init__(parent)
        self.columns = list(columns)  # (key, header)
        self.rows: list[dict[str, Any]] = []
        self.display: list[tuple[str, ...]] = []
        self.haystack: list[str] = []  # lower-cased display strings, for the text filter

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = list(rows)
        self._index()
        self.endResetModel()

    def _index(self) -> None:
        keys = [k for k, _ in self.columns]
        self.display = [tuple(display_text(k, r.get(k)) for k in keys) for r in self.rows]
        self.haystack = ["\x1f".join(d).lower() for d in self.display]

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        if not 0 <= column < len(self.columns):
            return
        key = self.columns[column][0]
        self.layoutAboutToBeChanged.emit()
        order_idx = sorted(
            range(len(self.rows)),
            key=lambda i: _sort_key(self.rows[i].get(key)),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )
        old = list(self.persistentIndexList())
        new_pos = {src: dst for dst, src in enumerate(order_idx)}
        self.rows = [self.rows[i] for i in order_idx]
        self.display = [self.display[i] for i in order_idx]
        self.haystack = [self.haystack[i] for i in order_idx]
        self.changePersistentIndexList(old, [self.index(new_pos[i.row()], i.column()) for i in old])
        self.layoutChanged.emit()

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole, Qt.ItemDataRole.ToolTipRole):
            text = self.display[index.row()][index.column()]  # tooltip: the full text of a narrowed cell
            return (text or None) if role == Qt.ItemDataRole.ToolTipRole else text
        row = self.rows[index.row()]
        key = self.columns[index.column()][0]
        value = row.get(key)
        if role == Qt.ItemDataRole.UserRole:
            return value
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section][1]
        return None

    def row_at(self, r: int) -> dict[str, Any]:
        return self.rows[r]

    def display_column(self, c: int) -> list[str]:
        return [d[c] for d in self.display]


class FilterProxy(QSortFilterProxyModel):
    """Case-insensitive text filter across all columns + optional exact column filter.

    Sorting is delegated to the source model (one ``list.sort``), so the proxy keeps the
    source order and never calls ``lessThan`` per pair of rows."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.setSortRole(Qt.ItemDataRole.UserRole)
        self.column_equals: tuple[int, str] | None = None
        self.needle = ""

    def _changing(self, apply: Any) -> None:
        if hasattr(self, "beginFilterChange"):  # Qt >= 6.10
            self.beginFilterChange()
            apply()
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            apply()
            self.invalidateFilter()

    def set_text(self, text: str) -> None:
        self._changing(lambda: setattr(self, "needle", text.lower()))

    def set_column_equals(self, column: int | None, value: str | None) -> None:
        self._changing(lambda: setattr(self, "column_equals", None if column is None or not value else (column, value)))

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        src = self.sourceModel()
        if isinstance(src, RowsModel):
            src.sort(column, order)
        else:
            super().sort(column, order)

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:
        src = self.sourceModel()
        if not isinstance(src, RowsModel):
            return True
        if self.column_equals is not None:
            col, val = self.column_equals
            if src.display[source_row][col] != val:
                return False
        return not self.needle or self.needle in src.haystack[source_row]

    def lessThan(self, left: Index, right: Index) -> bool:
        a, b = left.data(Qt.ItemDataRole.UserRole), right.data(Qt.ItemDataRole.UserRole)
        if a is None or b is None:
            return (a is None) and (b is not None)
        try:
            return bool(a < b)
        except TypeError:
            return str(a) < str(b)
