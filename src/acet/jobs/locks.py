"""Application locks with dead-owner detection (ACET-CON-001/002, ACC-105/106)."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso
from acet.storage.db import Database

_local_flights: dict[str, threading.Lock] = {}
_local_guard = threading.Lock()


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32")  # type: ignore[attr-defined,unused-ignore]
        h = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        kernel32.CloseHandle(h)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:  # a zombie has exited: it is not a live owner (Linux)
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            stat = fh.read()
        return stat[stat.rfind(")") + 2] != "Z"
    except OSError:
        return True


class LockBusy(Exception):
    pass


def try_acquire(db: Database, name: str, owner_id: str) -> bool:
    host = socket.gethostname()
    now = utc_now_iso()
    with db.transaction() as tx:
        row = tx.execute("SELECT owner_pid, owner_host FROM app_lock WHERE name=?", (name,)).fetchone()
        if row is not None:
            dead = row["owner_host"] == host and not pid_alive(int(row["owner_pid"]))
            if not dead:
                return False
            tx.execute("DELETE FROM app_lock WHERE name=?", (name,))  # ACC-106: recover a dead owner's lock
        tx.execute(
            "INSERT INTO app_lock(name, owner_id, owner_pid, owner_host, acquired_at, heartbeat_at) VALUES (?,?,?,?,?,?)",
            (name, owner_id, os.getpid(), host, now, now),
        )
    return True


def release(db: Database, name: str, owner_id: str) -> None:
    with db.transaction() as tx:
        tx.execute("DELETE FROM app_lock WHERE name=? AND owner_id=?", (name, owner_id))


@contextmanager
def single_flight(db: Database, key: str, *, wait_s: float = 3600.0, poll_s: float = 0.05) -> Iterator[bool]:
    """Exactly one holder per key across threads and processes (ACET-CON-001).

    Yields ``True`` to the computing holder. Followers block until the holder
    releases, then also receive ``True``; they are expected to re-check the cache
    first, which turns them into cache hits (ACC-105).
    """
    with _local_guard:
        local = _local_flights.setdefault(key, threading.Lock())
    owner = uuid7()
    deadline = time.monotonic() + wait_s
    with local:
        while not try_acquire(db, f"flight:{key}", owner):
            if time.monotonic() > deadline:
                raise LockBusy(key)
            time.sleep(poll_s)
        try:
            yield True
        finally:
            release(db, f"flight:{key}", owner)
