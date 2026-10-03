"""Resource policy (spec §26, ACC-031, ACET-RES-001)."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from acet.domain.error_codes import AcetError

MEMORY_BUDGET_FRACTION = 0.70


def available_memory_bytes() -> int | None:
    if sys.platform == "win32":
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(st)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):  # type: ignore[attr-defined]
            return int(st.ullAvailPhys)
        return None
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


@dataclass(frozen=True)
class ResourcePolicy:
    heavy_workers: int = 1
    light_workers: int = max(1, min(4, (os.cpu_count() or 2) // 2))
    memory_budget_fraction: float = MEMORY_BUDGET_FRACTION
    memory_cap_bytes: int | None = None
    disk_margin_bytes: int = 256 * 1024 * 1024

    def memory_budget(self) -> int | None:
        avail = available_memory_bytes()
        if avail is None:
            return self.memory_cap_bytes
        budget = int(avail * self.memory_budget_fraction)
        return min(budget, self.memory_cap_bytes) if self.memory_cap_bytes else budget


def disk_preflight(path: Path, estimated_bytes: int, policy: ResourcePolicy | None = None) -> None:
    """Refuse a heavy job cleanly before starting when space is insufficient (ACC-031)."""
    policy = policy or ResourcePolicy()
    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    if free < estimated_bytes + policy.disk_margin_bytes:
        raise AcetError(
            "ACET-IMP-003",
            "disk preflight refused heavy job",
            data={"estimated_bytes": estimated_bytes, "free_bytes": free, "estimate_quality": "LOW"},
        )
