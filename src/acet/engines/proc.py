"""Helpers for engine adapters running *inside* a supervised worker (process tree already contained)."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path


def tree_cpu_seconds(root_pid: int) -> float | None:
    """CPU time of a process tree (Linux /proc; Windows via the root process only)."""
    if sys.platform.startswith("linux"):
        try:
            hz = os.sysconf("SC_CLK_TCK")
            children: dict[int, list[int]] = {}
            stats: dict[int, float] = {}
            for d in os.listdir("/proc"):
                if not d.isdigit():
                    continue
                try:
                    raw = Path(f"/proc/{d}/stat").read_text()
                except OSError:
                    continue
                rest = raw[raw.rfind(")") + 2 :].split()
                ppid = int(rest[1])
                stats[int(d)] = (int(rest[11]) + int(rest[12])) / hz
                children.setdefault(ppid, []).append(int(d))
            total, stack = 0.0, [root_pid]
            while stack:
                pid = stack.pop()
                total += stats.get(pid, 0.0)
                stack += children.get(pid, [])
            return total
        except (OSError, ValueError):
            return None
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32")  # type: ignore[attr-defined]
        h = k32.OpenProcess(0x1000, False, root_pid)
        if not h:
            return None
        c, e, k, u = (wintypes.FILETIME() for _ in range(4))
        ok = k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u))
        k32.CloseHandle(h)
        if not ok:
            return None
        to_s = lambda ft: ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 1e7  # noqa: E731
        return float(to_s(k) + to_s(u))
    return None


def run_engine(
    argv: Sequence[str],
    *,
    cwd: Path,
    heartbeat: Callable[[], None],
    stop_requested: Callable[[], bool],
    env: dict[str, str] | None = None,
    on_line: Callable[[str], None] | None = None,
    captured: list[str] | None = None,
    capture_limit: int = 5000,
) -> int:
    """Run an engine as a child of the worker; forward its output; beat only on real activity
    (output lines or CPU progress of the engine tree)."""
    proc = subprocess.Popen(
        list(argv), cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env
    )
    assert proc.stdout is not None
    done = threading.Event()

    def cpu_watch() -> None:
        last = tree_cpu_seconds(proc.pid)
        while not done.wait(2.0):
            if stop_requested():
                proc.terminate()
            now = tree_cpu_seconds(proc.pid)
            if now is not None and last is not None and now > last + 0.05:
                heartbeat()
            last = now

    threading.Thread(target=cpu_watch, daemon=True).start()
    for raw in iter(proc.stdout.readline, b""):
        line = raw.decode("utf-8", "replace").rstrip("\n")
        print(line, flush=True)
        heartbeat()
        if on_line is not None:
            on_line(line)
        if captured is not None:
            captured.append(line)
            if len(captured) > capture_limit:
                del captured[: len(captured) - capture_limit]
    code = proc.wait()
    done.set()
    time.sleep(0)
    return code
