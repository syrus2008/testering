"""Synthetic, inert fixtures. The PE images are header-only byte strings built
in memory: they contain no code and are never executed (ACC-004)."""

from __future__ import annotations

import struct
from pathlib import Path

IMAGE_FILE_DLL = 0x2000


def make_pe(*, machine: int = 0x8664, subsystem: int = 3, dll: bool = False, payload: bytes = b"") -> bytes:
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    pe32_plus = machine in (0x8664, 0xAA64)
    opt_size = 240 if pe32_plus else 224
    characteristics = 0x0002 | (IMAGE_FILE_DLL if dll else 0)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, opt_size, characteristics)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32_plus else 0x10B)
    struct.pack_into("<H", opt, 68, subsystem)
    return bytes(dos) + coff + bytes(opt) + payload


def driver(payload: bytes = b"drv") -> bytes:
    return make_pe(subsystem=1, payload=payload)


def dll(payload: bytes = b"dll") -> bytes:
    return make_pe(dll=True, subsystem=2, payload=payload)


def exe(payload: bytes = b"exe") -> bytes:
    return make_pe(subsystem=2, payload=payload)


def write_build(folder: Path, files: dict[str, bytes]) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        p = folder / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return folder


def build_a(folder: Path) -> Path:
    return write_build(
        folder,
        {
            "Fict.sys": driver(b"v1-driver"),
            "FictSvc.exe": exe(b"v1-service"),
            "fict_user.dll": dll(b"v1-dll"),
            "settings.json": b'{"channel": "live"}\n',
        },
    )


def build_b(folder: Path) -> Path:
    """Build B shares the DLL and config with A; driver and service changed."""
    return write_build(
        folder,
        {
            "Fict.sys": driver(b"v2-driver"),
            "FictSvc.exe": exe(b"v2-service"),
            "fict_user.dll": dll(b"v1-dll"),
            "settings.json": b'{"channel": "live"}\n',
        },
    )
