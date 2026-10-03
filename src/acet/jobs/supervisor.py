"""Supervisor for external worker/provider processes (ACET-ARCH-002, §60, ACET-JOB-003, ACET-OBS-002).

* The whole process tree is a unit: a Windows Job Object (kill-on-close) or a
  POSIX session/process group. Hard stop kills the unit, so no descendant
  survives (ACC-052).
* Two-stage termination: graceful request, delay, then hard kill. The method
  used is recorded (ACET-WIN-002).
* stdout/stderr are drained by threads into bounded logs keeping the head, the
  tail and error/warning counters (ACC-087). Completion never waits on pipe EOF
  alone (ACET-WIN-003).
* Watchdog: soft timeout → graceful stop; hard timeout → kill; heartbeat loss
  → HUNG → kill (ACET-JOB-003). Heartbeat = heartbeat-file mtime or log activity.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import IO, Any

DEFAULT_LOG_HEAD = 256 * 1024
DEFAULT_LOG_TAIL = 256 * 1024
ERROR_RE = re.compile(rb"\b(ERROR|SEVERE|Exception|Traceback)\b")
WARN_RE = re.compile(rb"\bWARN(ING)?\b")


class Termination(StrEnum):
    NORMAL = "normal"
    TIMEOUT = "timeout"
    KILLED = "killed"
    CRASH = "crash"
    UNKNOWN = "unknown"


@dataclass
class Limits:
    soft_timeout_s: float | None = None
    hard_timeout_s: float | None = None
    heartbeat_timeout_s: float | None = None
    grace_s: float = 5.0
    memory_limit_bytes: int | None = None
    log_head_bytes: int = DEFAULT_LOG_HEAD
    log_tail_bytes: int = DEFAULT_LOG_TAIL


@dataclass
class LogStats:
    total_bytes: int = 0
    total_lines: int = 0
    error_lines: int = 0
    warning_lines: int = 0
    truncated: bool = False
    last_activity: float = 0.0


@dataclass
class ProcessResult:
    exit_code: int | None
    termination: Termination
    stop_method: str | None
    wall_ms: int
    peak_rss_bytes: int | None
    stdout: LogStats
    stderr: LogStats
    stdout_path: Path
    stderr_path: Path
    hung: bool = False
    cancelled: bool = False
    notes: list[str] = field(default_factory=list)

    def to_metrics(self) -> dict[str, Any]:
        return {
            "wall_ms": self.wall_ms,
            "peak_rss_bytes": self.peak_rss_bytes,
            "exit_code": self.exit_code,
            "termination": self.termination.value,
            "stop_method": self.stop_method,
            "log": {
                "stdout_bytes": self.stdout.total_bytes,
                "stderr_bytes": self.stderr.total_bytes,
                "error_lines": self.stdout.error_lines + self.stderr.error_lines,
                "warning_lines": self.stdout.warning_lines + self.stderr.warning_lines,
                "truncated": self.stdout.truncated or self.stderr.truncated,
            },
        }


class _BoundedDrain(threading.Thread):
    """Read a pipe to exhaustion; keep head + tail; count error/warning lines."""

    def __init__(self, pipe: IO[bytes], dest: Path, limits: Limits) -> None:
        super().__init__(daemon=True)
        self.pipe, self.dest, self.limits = pipe, dest, limits
        self.stats = LogStats(last_activity=time.monotonic())
        self.head = bytearray()
        self.tail: deque[bytes] = deque()
        self.tail_size = 0

    def run(self) -> None:
        partial = b""
        try:
            for chunk in iter(
                lambda: self.pipe.read1(65536) if hasattr(self.pipe, "read1") else self.pipe.read(65536), b""
            ):
                self.stats.last_activity = time.monotonic()
                self.stats.total_bytes += len(chunk)
                lines = (partial + chunk).split(b"\n")
                partial = lines.pop()
                for ln in lines:
                    self._line(ln + b"\n")
            if partial:
                self._line(partial)
        except (OSError, ValueError):
            pass
        finally:
            self.flush()

    def _line(self, ln: bytes) -> None:
        self.stats.total_lines += 1
        if ERROR_RE.search(ln):
            self.stats.error_lines += 1
        elif WARN_RE.search(ln):
            self.stats.warning_lines += 1
        room = self.limits.log_head_bytes - len(self.head)
        if room > 0:
            self.head += ln[:room]
            ln = ln[room:]
            if not ln:
                return
        self.tail.append(ln)
        self.tail_size += len(ln)
        while self.tail_size > self.limits.log_tail_bytes and self.tail:
            self.tail_size -= len(self.tail.popleft())
            self.stats.truncated = True

    def flush(self) -> None:
        tmp = self.dest.with_name(self.dest.name + ".tmp")
        with open(tmp, "wb") as fh:
            fh.write(bytes(self.head))
            if self.stats.truncated:
                fh.write(b"\n[... ACET: log truncated (OBS-002); counters kept ...]\n")
            fh.write(b"".join(self.tail))
            fh.write(
                f"\n[ACET log stats: bytes={self.stats.total_bytes} lines={self.stats.total_lines} "
                f"errors={self.stats.error_lines} warnings={self.stats.warning_lines}]\n".encode()
            )
        os.replace(tmp, self.dest)


def _minimal_env(extra: Mapping[str, str] | None) -> dict[str, str]:
    """§61: minimal environment variables for workers."""
    keep = (
        "PATH",
        "SYSTEMROOT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "LANG",
        "LC_ALL",
        "JAVA_HOME",
        "PYTHONPATH",
        "PYTHONIOENCODING",
        "COMSPEC",
        "WINDIR",
        "LOCALAPPDATA",
        "APPDATA",
        "XDG_RUNTIME_DIR",
        "JAVA_TOOL_OPTIONS",
    )
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra or {})
    return env


def _posix_preexec(memory_limit: int | None) -> Callable[[], None] | None:
    if memory_limit is None:
        return None

    def apply() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))  # type: ignore[attr-defined,unused-ignore]

    return apply


def run_supervised(
    argv: Sequence[str],
    *,
    workdir: Path,
    log_dir: Path,
    limits: Limits | None = None,
    env: Mapping[str, str] | None = None,
    heartbeat_file: Path | None = None,
    cancel_event: threading.Event | None = None,
    graceful_stop_file: Path | None = None,
    poll_s: float = 0.05,
) -> ProcessResult:
    limits = limits or Limits()
    log_dir.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    out_path, err_path = log_dir / "stdout.log", log_dir / "stderr.log"
    start = time.monotonic()
    job = None
    rusage_before: int | None = None
    if sys.platform == "win32":
        from acet.jobs.winjob import CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED, JobObject

        job = JobObject(limits.memory_limit_bytes)
        proc = subprocess.Popen(
            list(argv),
            cwd=workdir,
            env=_minimal_env(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        )
        try:
            job.assign(proc)
            job.resume(proc)
        except OSError:
            # Never leave a suspended, uncontained child behind.
            proc.kill()
            proc.wait()
            job.close()
            raise
    else:
        rusage_before = _children_maxrss()
        proc = subprocess.Popen(
            list(argv),
            cwd=workdir,
            env=_minimal_env(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=_posix_preexec(limits.memory_limit_bytes),
        )
    assert proc.stdout is not None and proc.stderr is not None
    d_out = _BoundedDrain(proc.stdout, out_path, limits)
    d_err = _BoundedDrain(proc.stderr, err_path, limits)
    d_out.start()
    d_err.start()

    termination = Termination.NORMAL
    stop_method: str | None = None
    hung = cancelled = False
    soft_sent_at: float | None = None
    notes: list[str] = []

    def last_heartbeat() -> float:
        hb = max(d_out.stats.last_activity, d_err.stats.last_activity)
        if heartbeat_file is not None:
            try:
                age = time.time() - heartbeat_file.stat().st_mtime
                hb = max(hb, time.monotonic() - age)
            except OSError:
                pass
        return hb

    def graceful() -> None:
        nonlocal stop_method
        stop_method = "graceful"
        if graceful_stop_file is not None:
            graceful_stop_file.touch()
        try:
            if sys.platform == "win32":
                proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined,unused-ignore]
            else:
                os.killpg(proc.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass

    def hard() -> None:
        nonlocal stop_method
        stop_method = "terminate_job_object" if job is not None else "killpg_sigkill"
        if job is not None:
            job.terminate()
        else:
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)

    while proc.poll() is None:
        now = time.monotonic()
        elapsed = now - start
        if soft_sent_at is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                termination = Termination.KILLED
                graceful()
                soft_sent_at = now
            elif limits.soft_timeout_s is not None and elapsed > limits.soft_timeout_s:
                termination = Termination.TIMEOUT
                notes.append("soft timeout reached")
                graceful()
                soft_sent_at = now
            elif limits.heartbeat_timeout_s is not None and now - last_heartbeat() > limits.heartbeat_timeout_s:
                hung = True
                termination = Termination.TIMEOUT
                notes.append("heartbeat lost: HUNG")
                hard()
                soft_sent_at = now
        elif now - soft_sent_at > limits.grace_s:
            hard()
        if (
            limits.hard_timeout_s is not None
            and elapsed > limits.hard_timeout_s
            and stop_method != "terminate_job_object"
        ):
            termination = Termination.TIMEOUT
            notes.append("hard timeout reached")
            hard()
            break
        time.sleep(poll_s)
    try:
        exit_code: int | None = proc.wait(timeout=limits.grace_s + 5)
    except subprocess.TimeoutExpired:
        hard()
        exit_code = proc.wait(timeout=10)
    # The process group may still hold descendants (e.g. a grandchild that ignored the
    # signal): the unit always dies with the run.
    if job is not None:
        peak = job.peak_memory()
        job.terminate()
        job.close()
    else:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        after = _children_maxrss()
        peak = after if after is not None and (rusage_before is None or after >= rusage_before) else None
    # Never wait indefinitely for pipe EOF (a surviving descendant could hold the pipe).
    d_out.join(timeout=5)
    d_err.join(timeout=5)
    if d_out.is_alive() or d_err.is_alive():
        notes.append("log drain did not reach EOF; logs flushed as-is")
        d_out.flush()
        d_err.flush()
    if (termination is Termination.NORMAL and exit_code is not None and exit_code < 0) or (
        termination is Termination.NORMAL
        and exit_code not in (0, None)
        and sys.platform == "win32"
        and exit_code >= 0xC0000000
    ):
        termination = Termination.CRASH
    return ProcessResult(
        exit_code=exit_code,
        termination=termination,
        stop_method=stop_method,
        wall_ms=int((time.monotonic() - start) * 1000),
        peak_rss_bytes=peak,
        stdout=d_out.stats,
        stderr=d_err.stats,
        stdout_path=out_path,
        stderr_path=err_path,
        hung=hung,
        cancelled=cancelled,
        notes=notes,
    )


def _children_maxrss() -> int | None:
    try:
        import resource

        kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss  # type: ignore[attr-defined,unused-ignore]
        return int(kb if sys.platform == "darwin" else kb * 1024)
    except (ImportError, OSError):
        return None
