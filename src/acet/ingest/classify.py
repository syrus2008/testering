"""CLASSIFY stage — static format sniffing and role proposal (ACET-IMP-001, §13).

Reads at most the first 64 KiB of a file. Nothing is loaded as code: headers are
parsed with ``struct`` from bytes. The result is a *proposal* with a confidence
class; human corrections are stored separately as assertions.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from acet.domain.enums import ArtifactFormat, ComponentRole, ConfidenceClass

HEADER_READ = 64 * 1024

MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C4: "arm", 0x200: "ia64"}
IMAGE_FILE_DLL = 0x2000
SUBSYSTEM_NATIVE = 1
SUBSYSTEM_GUI = 2
SUBSYSTEM_CUI = 3

CONFIG_EXTS = {".json", ".ini", ".cfg", ".conf", ".xml", ".toml", ".yaml", ".yml", ".config", ".manifest"}


@dataclass(frozen=True)
class Classification:
    format: ArtifactFormat
    arch: str | None
    role: ComponentRole
    confidence: ConfidenceClass
    mime_hint: str | None
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PeHeader:
    machine: int
    characteristics: int
    magic: int
    subsystem: int | None


def parse_pe_header(data: bytes) -> PeHeader | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return None
    machine, _nsec, _ts, _sym, _nsym, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    if opt_size < 2 or opt + 2 > len(data):
        return PeHeader(machine, characteristics, 0, None)
    (magic,) = struct.unpack_from("<H", data, opt)
    subsystem = None
    if opt_size >= 70 and opt + 70 <= len(data):
        (subsystem,) = struct.unpack_from("<H", data, opt + 68)
    return PeHeader(machine, characteristics, magic, subsystem)


def _looks_text(data: bytes) -> bool:
    if not data or b"\0" in data[:4096]:
        return False
    try:
        data[:4096].decode("utf-8")
    except UnicodeDecodeError:
        # A cut multi-byte sequence at the boundary is still text.
        try:
            data[:4093].decode("utf-8")
        except UnicodeDecodeError:
            return False
    return True


def classify_bytes(head: bytes, filename: str) -> Classification:
    ext = Path(filename).suffix.lower()
    pe = parse_pe_header(head)
    if pe is not None:
        fmt = {0x10B: ArtifactFormat.PE32, 0x20B: ArtifactFormat.PE32_PLUS}.get(pe.magic, ArtifactFormat.UNKNOWN_BINARY)
        arch = MACHINES.get(pe.machine)
        reasons = [f"PE magic=0x{pe.magic:x}", f"machine={arch or hex(pe.machine)}", f"subsystem={pe.subsystem}"]
        if pe.subsystem == SUBSYSTEM_NATIVE:
            conf = ConfidenceClass.HIGH if ext == ".sys" else ConfidenceClass.MEDIUM
            return Classification(
                fmt,
                arch,
                ComponentRole.KERNEL_DRIVER,
                conf,
                "application/vnd.microsoft.portable-executable",
                tuple(reasons),
            )
        if pe.characteristics & IMAGE_FILE_DLL:
            conf = ConfidenceClass.HIGH if ext == ".dll" else ConfidenceClass.MEDIUM
            return Classification(
                fmt,
                arch,
                ComponentRole.USER_MODULE,
                conf,
                "application/vnd.microsoft.portable-executable",
                (*reasons, "IMAGE_FILE_DLL"),
            )
        if pe.subsystem in (SUBSYSTEM_GUI, SUBSYSTEM_CUI):
            # SERVICE/LAUNCHER cannot be told apart statically without profile hints.
            return Classification(
                fmt,
                arch,
                ComponentRole.EXECUTABLE,
                ConfidenceClass.MEDIUM,
                "application/vnd.microsoft.portable-executable",
                tuple(reasons),
            )
        return Classification(
            fmt,
            arch,
            ComponentRole.OTHER,
            ConfidenceClass.LOW,
            "application/vnd.microsoft.portable-executable",
            tuple(reasons),
        )
    if _looks_text(head):
        if ext in CONFIG_EXTS:
            return Classification(
                ArtifactFormat.TEXT,
                None,
                ComponentRole.CONFIGURATION,
                ConfidenceClass.MEDIUM,
                "text/plain",
                (f"text, extension {ext}",),
            )
        return Classification(
            ArtifactFormat.TEXT, None, ComponentRole.DATA, ConfidenceClass.LOW, "text/plain", ("text",)
        )
    if not head:
        return Classification(
            ArtifactFormat.UNKNOWN, None, ComponentRole.DATA, ConfidenceClass.LOW, None, ("empty file",)
        )
    return Classification(
        ArtifactFormat.UNKNOWN_BINARY, None, ComponentRole.OTHER, ConfidenceClass.LOW, None, ("unrecognized binary",)
    )


def classify_file(path: Path) -> Classification:
    with open(path, "rb") as fh:
        head = fh.read(HEADER_READ)
    return classify_bytes(head, path.name)
