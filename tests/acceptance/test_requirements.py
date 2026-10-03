"""ACET-TRACE-001/002 (ACC-116/117) and small requirement checks."""

from __future__ import annotations

import zipfile

import pytest
from tools.gen_traceability import REQ_OUT, build, build_requirements, render_requirements

from acet.domain.error_codes import AcetError
from acet.platform.doctor import workspace_checks
from acet.reporting.acetpack import ArchiveLimits, check_archive


@pytest.mark.acceptance("ACC-116")
def test_every_requirement_is_implemented_and_verified_or_waived():
    reqs = build_requirements()
    assert len(reqs["requirements"]) == 135
    bad = [r["id"] for r in reqs["requirements"] if r["status"] not in ("covered", "waived")]
    assert not bad, bad
    assert REQ_OUT.read_text(encoding="utf-8") == render_requirements()


@pytest.mark.acceptance("ACC-117")
def test_every_acceptance_criterion_has_test_or_versioned_protocol():
    rows = build()["criteria"]
    missing = [r["id"] for r in rows if r["status"] not in ("automated", "manual_protocol")]
    assert not missing, missing


def test_encrypted_archive_entries_refused(tmp_path):
    import struct

    p = tmp_path / "enc.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("manifest.json", b"{}")
        z.writestr("checksums.txt", b"")
    raw = bytearray(p.read_bytes())  # mark the first member as encrypted (general purpose bit 0)
    struct.pack_into("<H", raw, 6, struct.unpack_from("<H", raw, 6)[0] | 1)
    cd = raw.find(b"PK\x01\x02")
    struct.pack_into("<H", raw, cd + 8, struct.unpack_from("<H", raw, cd + 8)[0] | 1)
    p.write_bytes(bytes(raw))
    with zipfile.ZipFile(p) as z, pytest.raises(AcetError) as ei:
        check_archive(z, ArchiveLimits())
    assert "password" in str(ei.value)


def test_network_workspace_location_warns(ws):
    from pathlib import PureWindowsPath

    from acet.platform.doctor import location_check

    checks, _ = workspace_checks(ws)
    assert next(c for c in checks if c.name == "workspace.location").status.value == "OK"
    assert location_check(PureWindowsPath(r"\\fileserver\share\ws")).status.value == "WARN"  # type: ignore[arg-type]
    assert location_check(PureWindowsPath("C:/Users/x/ws")).status.value == "OK"  # type: ignore[arg-type]
