"""Sleep prevention during heavy jobs (ACET-RES-002, ACC-094).

Only requests "system required" (never display), only when the user allowed it,
and is always restored — on success, failure and cancellation.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001

_state = {"active": 0}


def _set(flags: int) -> None:
    if sys.platform == "win32":
        import ctypes

        ctypes.windll.kernel32.SetThreadExecutionState(flags)  # type: ignore[attr-defined]


def prevention_active() -> bool:
    return _state["active"] > 0


@contextmanager
def keep_awake(allowed: bool) -> Iterator[None]:
    if not allowed:
        yield
        return
    _state["active"] += 1
    _set(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
    try:
        yield
    finally:
        _state["active"] -= 1
        if _state["active"] == 0:
            _set(ES_CONTINUOUS)
