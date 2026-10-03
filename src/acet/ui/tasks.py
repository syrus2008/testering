"""Background execution: nothing slow ever runs on the UI thread (§106, ACC-029/118)."""

from __future__ import annotations

import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from acet.domain.error_codes import AcetError, classify_exception


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(object, str)


class _Task(QRunnable):
    def __init__(self, fn: Callable[..., Any], args: tuple[Any, ...], ws_path: Path | None, read_only: bool) -> None:
        super().__init__()
        self.fn, self.args, self.ws_path, self.read_only = fn, args, ws_path, read_only
        self.signals = _Signals()
        self.setAutoDelete(True)

    def run(self) -> None:
        ws = None
        try:
            if self.ws_path is not None:
                from acet.application.workspace import open_workspace

                ws = open_workspace(self.ws_path, read_only=self.read_only)
                result = self.fn(ws, *self.args)
            else:
                result = self.fn(*self.args)
            self.signals.done.emit(result)
        except BaseException as exc:  # mapped to the closed taxonomy (ACET-CLOSE-002)
            err = classify_exception(exc) if not isinstance(exc, AcetError) else exc
            self.signals.failed.emit(err, traceback.format_exc())
        finally:
            if ws is not None:
                ws.close()


class TaskRunner(QObject):
    """Runs callables on a thread pool; each task gets its own workspace connection."""

    busy_changed = Signal(int)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(4)
        self.active = 0
        self._keep: set[_Task] = set()

    def run(
        self,
        fn: Callable[..., Any],
        *args: Any,
        ws_path: Path | None = None,
        read_only: bool = False,
        on_done: Callable[[Any], None] | None = None,
        on_error: Callable[[AcetError, str], None] | None = None,
    ) -> None:
        task = _Task(fn, args, ws_path, read_only)
        self._keep.add(task)
        self.active += 1
        self.busy_changed.emit(self.active)

        def finish() -> None:
            self.active -= 1
            self._keep.discard(task)
            self.busy_changed.emit(self.active)

        def done(res: object) -> None:
            finish()
            if on_done:
                on_done(res)

        def failed(err: object, tb: str) -> None:
            finish()
            if on_error:
                on_error(err, tb)  # type: ignore[arg-type]

        task.signals.done.connect(done)
        task.signals.failed.connect(failed)
        self.pool.start(task)

    def wait(self, ms: int = 60_000) -> bool:
        return bool(self.pool.waitForDone(ms))
