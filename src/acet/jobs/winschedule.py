"""Windows Task Scheduler registration for periodic ACET commands (current user, no elevation).

Process control lives in ``acet.jobs`` (with the supervisor): the scheduled command is ACET itself, never an
analysed artifact (ADR-0010)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from acet.domain.error_codes import AcetError

TASK_NAME = "ACET Watch"


def _quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def task_command(acet_args: list[str], minutes: int) -> list[str]:
    """``schtasks /Create`` running ``acet <acet_args>`` every ``minutes`` without a console window."""
    exe = Path(sys.executable)
    if getattr(sys, "frozen", False):
        target = [str(exe), *acet_args]
    else:
        pyw = exe.with_name("pythonw.exe")
        target = [str(pyw if pyw.is_file() else exe), "-m", "acet", *acet_args]
    tr = " ".join(_quote(a) for a in target)
    return ["schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", str(minutes), "/TN", TASK_NAME, "/TR", tr]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    if sys.platform != "win32":
        raise AcetError("ACET-WATCH-001", "background checks while ACET is closed use the Windows Task Scheduler")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def register(cmd: list[str]) -> str:
    r = _run(cmd)
    if r.returncode != 0:
        raise AcetError("ACET-WATCH-001", f"Task Scheduler refused the task: {(r.stderr or r.stdout).strip()}")
    return (r.stdout or "").strip()


def unregister() -> str:
    r = _run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME])
    return (r.stdout or r.stderr or "").strip()
