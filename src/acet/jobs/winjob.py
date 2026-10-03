"""Windows Job Object wrapper (ACET-WIN-001/002). Imported only on Windows."""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]

JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x200
PROCESS_ALL_ACCESS = 0x1F0FFF
CREATE_SUSPENDED = 0x4
CREATE_NEW_PROCESS_GROUP = 0x200
CREATE_NO_WINDOW = 0x08000000


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        (n, ctypes.c_ulonglong)
        for n in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JobObject:
    def __init__(self, memory_limit_bytes: int | None = None) -> None:
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined,unused-ignore]
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if memory_limit_bytes:
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY
            info.JobMemoryLimit = memory_limit_bytes
        if not kernel32.SetInformationJobObject(
            self.handle, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined,unused-ignore]

    def assign(self, proc: subprocess.Popen[bytes]) -> None:
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        try:
            if not kernel32.AssignProcessToJobObject(self.handle, h):
                raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined,unused-ignore]
        finally:
            kernel32.CloseHandle(h)

    def resume(self, proc: subprocess.Popen[bytes]) -> None:
        """Resume a process created with CREATE_SUSPENDED (assigned before it can spawn children)."""
        ntdll = ctypes.WinDLL("ntdll")  # type: ignore[attr-defined,unused-ignore]
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, proc.pid)
        try:
            ntdll.NtResumeProcess(h)
        finally:
            kernel32.CloseHandle(h)

    def terminate(self, exit_code: int = 1) -> None:
        kernel32.TerminateJobObject(self.handle, exit_code)

    def peak_memory(self) -> int | None:
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ok = kernel32.QueryInformationJobObject(
            self.handle, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info), None
        )
        return int(info.PeakJobMemoryUsed) if ok else None

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)  # KILL_ON_JOB_CLOSE reaps any survivor
            self.handle = None
