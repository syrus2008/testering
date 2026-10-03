"""Optional credentials (spec §111, ACET-SEC-006, ACC-125).

The Core needs no secret. Optional network providers store tokens with Windows
DPAPI (current-user scope); configuration only holds an opaque reference. On
platforms without an OS credential store integration, storing a secret is refused
rather than written in clear text.
"""

from __future__ import annotations

import base64
import ctypes
import sys
from pathlib import Path

from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.platform.paths import acet_home


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32")  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32")  # type: ignore[attr-defined]
    buf = ctypes.create_string_buffer(data, len(data))
    inp = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inp), None, None, None, None, 0x1, ctypes.byref(out)):  # CRYPTPROTECT_UI_FORBIDDEN
        raise AcetError("ACET-INT-001", "DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def _dir() -> Path:
    d = acet_home() / "config" / "secrets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def store_secret(value: str) -> str:
    """Return an opaque reference to put in configuration."""
    if sys.platform != "win32":
        raise AcetError("ACET-PROF-001", "no OS credential store integration on this platform; secret not stored")
    ref = f"dpapi:{uuid7()}"
    (_dir() / ref.split(":", 1)[1]).write_bytes(base64.b64encode(_dpapi(value.encode("utf-8"), True)))
    return ref


def load_secret(ref: str) -> str:
    if not ref.startswith("dpapi:") or sys.platform != "win32":
        raise AcetError("ACET-PROF-001", "unknown secret reference")
    blob = base64.b64decode((_dir() / ref.split(":", 1)[1]).read_bytes())
    return _dpapi(blob, False).decode("utf-8")
