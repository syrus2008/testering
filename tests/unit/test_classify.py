from __future__ import annotations

from acet.domain.enums import ArtifactFormat, ComponentRole, ConfidenceClass
from acet.ingest.classify import classify_bytes, parse_pe_header
from tests.fixtures import dll, driver, exe, make_pe


def test_driver_dll_exe_classification():
    c = classify_bytes(driver(), "x.sys")
    assert (c.format, c.arch, c.role, c.confidence) == (
        ArtifactFormat.PE32_PLUS,
        "x64",
        ComponentRole.KERNEL_DRIVER,
        ConfidenceClass.HIGH,
    )
    assert classify_bytes(driver(), "x.bin").confidence is ConfidenceClass.MEDIUM
    assert classify_bytes(dll(), "x.dll").role is ComponentRole.USER_MODULE
    assert classify_bytes(exe(), "x.exe").role is ComponentRole.EXECUTABLE
    c32 = classify_bytes(make_pe(machine=0x14C), "a.exe")
    assert (c32.format, c32.arch) == (ArtifactFormat.PE32, "x86")


def test_non_pe_inputs():
    assert classify_bytes(b'{"a":1}', "c.json").role is ComponentRole.CONFIGURATION
    assert classify_bytes(b"hello", "readme.txt").role is ComponentRole.DATA
    assert classify_bytes(b"\x00\x01\x02", "blob.bin").format is ArtifactFormat.UNKNOWN_BINARY
    assert classify_bytes(b"", "empty").format is ArtifactFormat.UNKNOWN


def test_malformed_pe_does_not_crash():
    assert parse_pe_header(b"MZ" + b"\xff" * 62) is None  # e_lfanew far out of range
    assert parse_pe_header(b"MZ") is None
    trunc = make_pe()[: 0x80 + 26]
    assert parse_pe_header(trunc) is not None
