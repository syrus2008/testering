"""Engine Pack Manager (ADR-0013): download/verify/install/repair/rollback/recover, fail-closed trust,
explicit errors, cancellation, crash recovery and profile gating (ACC-ENGINE-002/003/004/006)."""

from __future__ import annotations

import errno
import hashlib
import http.server
import json
import os
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest

from acet.domain.error_codes import AcetError
from acet.platform import ed25519, engine_packs, signing
from acet.platform import engine_manager as em

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.build_engine_pack import build, index_entry, make_archive, make_index  # noqa: E402

SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
OTHER = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
VERIFIED = {"verdict": "VERIFIED", "engine_mode": "live", "providers": {"ghidra": {"available": True},
            "java": {"available": True}}}  # fmt: skip


def _staging_empty() -> bool:
    return not em.staging_dir().exists() or not any(em.staging_dir().iterdir())


def ok_health(_d: Path, _m: dict[str, Any]) -> dict[str, Any]:
    return VERIFIED


@pytest.fixture(autouse=True)
def trust(monkeypatch):
    key = {
        "key_id": "rel",
        "alg": "ed25519",
        "public_key": ed25519.public_key(SECRET).hex(),
        "purposes": ["engine-pack"],
    }
    monkeypatch.setattr(signing, "_bundled_store", lambda: {"keys": [key]})
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_GHIDRA_REPLAY_DIR", "ACET_GHIDRIFF_PYTHON", "JAVA_HOME"):
        monkeypatch.delenv(k, raising=False)


def make_pack(tmp: Path, version: str = "1.0.0", *, extra: dict[str, bytes] | None = None, key: bytes = SECRET) -> Path:
    """A structurally real pack: Ghidra layout + private Java runtime (files are never executed here)."""
    src = tmp / f"src-{version}"
    files = {
        "ghidra/support/analyzeHeadless": b"#!/bin/sh\n",
        "ghidra/support/launch.properties": b"JAVA_HOME_OVERRIDE=\nVMARGS=-Xshare:off\n",
        "ghidra/Ghidra/application.properties": b"application.version=11.4.2\n",
        "ghidra/Ghidra/Features/Jython/data/Lib/isql$py.class": b"\xca\xfe",
        "runtime/java/bin/java": b"#!/bin/sh\n",
        "runtime/java/bin/java.exe": b"MZ",
        "runtime/java/release": b'JAVA_VERSION="21.0.5"\n',
        "licenses/Ghidra-LICENSE.txt": b"Apache-2.0",
        **(extra or {}),
    }
    for rel, data in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (src / "ghidra/support/analyzeHeadless").chmod(0o755)
    (src / "runtime/java/bin/java").chmod(0o755)
    cfg = {
        "id": "acet-engines",
        "version": version,
        "supported_acet": ">=0.1,<2.0",
        "sources": {"ghidra": str(src / "ghidra"), "runtime": str(src / "runtime"), "licenses": str(src / "licenses")},
        "runtime": {"java": {"path": "runtime/java", "version": "21.0.5", "vendor": "Eclipse Temurin"}},
        "components": [
            {
                "id": "java",
                "name": "Eclipse Temurin JDK",
                "version": "21.0.5",
                "license": "GPL-2.0-only WITH Classpath-exception-2.0",
            },
            {"id": "ghidra", "name": "Ghidra", "version": "11.4.2", "license": "Apache-2.0"},
        ],
        "providers": [
            {
                "provider_id": "ghidra",
                "provider_version": "11.4.2",
                "protocol_version": 1,
                "capabilities": ["DISASSEMBLY", "FUNCTION_EXTRACTION"],
                "executable": "ghidra",
                "license_mode": "bundled",
                "health_check": "acet doctor --full",
                "supported_formats": ["PE32+"],
                "supported_architectures": ["x64"],
            },
        ],
        "licenses": [
            {
                "component": "ghidra",
                "spdx": "Apache-2.0",
                "redistribution": "yes",
                "bundling": "bundled",
                "version_audited": "11.4.2",
            }
        ],
    }
    pack = build(cfg, tmp / f"pack-{version}", key, "rel")
    return make_archive(pack, tmp / f"acet-engines-{version}.acetengine")


class Server:
    """Local HTTP distribution with Range support and fault injection."""

    def __init__(self, root: Path) -> None:
        self.root, self.cut_after, self.status, self.ranges = root, None, None, []
        srv = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_GET(self) -> None:
                if srv.status:
                    self.send_response(srv.status)
                    self.end_headers()
                    return
                p = srv.root / self.path.lstrip("/")
                if not p.is_file():
                    self.send_response(404)
                    self.end_headers()
                    return
                data = p.read_bytes()
                start = 0
                rng = self.headers.get("Range")
                if p.suffix == ".acetengine":
                    srv.ranges.append(rng)
                if rng:
                    start = int(rng.split("=")[1].split("-")[0])
                    self.send_response(206)
                else:
                    self.send_response(200)
                body = data[start:]
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if srv.cut_after is not None and p.suffix == ".acetengine":
                    self.wfile.write(body[: srv.cut_after])
                    srv.cut_after = None
                    return
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


@pytest.fixture
def dist(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    s = Server(root)

    def publish(archive: Path, *, key: bytes = SECRET, sha: str | None = None) -> str:
        (root / archive.name).write_bytes(archive.read_bytes())
        pack_dir = archive.parent / f"pack-{archive.stem.split('-')[-1]}"
        entry = index_entry(pack_dir, archive, f"{s.url}/{archive.name}")
        if sha:
            entry["archive_sha256"] = sha
        (root / "index.json").write_text(json.dumps(make_index([entry], key, "rel")))
        return f"{s.url}/index.json"

    s.publish = publish  # type: ignore[attr-defined]
    yield s
    s.httpd.shutdown()


def _install(url: str, **kw: Any) -> em.InstallResult:
    seen: list[dict[str, Any]] = []
    res = em.install_from_distribution(consent=lambda e: seen.append(e) or True, index_url=url,
                                       health_check=kw.pop("health_check", ok_health), **kw)  # fmt: skip
    res.consent_entry = seen[0] if seen else None  # type: ignore[attr-defined]
    return res


# ------------------------------------------------------------------------------------------- happy path
@pytest.mark.acceptance("ACC-034", "ACC-057")
def test_download_verify_install_activate(tmp_path, dist):
    url = dist.publish(make_pack(tmp_path))
    res = _install(url)
    assert res.state == "READY" and res.pack == "acet-engines-1.0.0"
    assert res.steps == ["VERIFYING", "EXTRACTING", "VALIDATING", "HEALTH_CHECK", "ACTIVATED"]
    e = res.consent_entry  # what the consent dialog shows
    assert (
        e["archive_size"] > 0 and e["installed_size"] > 0 and {c["id"] for c in e["components"]} == {"java", "ghidra"}
    )
    assert e["licenses"][0]["spdx"] == "Apache-2.0"
    act = em.active_pack()
    assert act["version"] == "1.0.0" and act["verification"]["verdict"] == "VERIFIED"
    assert os.access(Path(act["path"]) / "runtime/java/bin/java", os.X_OK)
    st = em.status()
    assert {c["id"]: c["state"] for c in st["components"]}["java"] == "READY"
    assert st["components"][0]["source"] == "engine-pack"
    assert st["profiles"]["FAST"]["state"] == "READY"
    log = em.log_path().read_text()
    for step in ("RESOLVED", "DOWNLOAD_START", "DOWNLOAD_VERIFIED", "INSTALL_START", "HEALTH_CHECK", "ACTIVATED"):
        assert step in log


def test_no_download_without_consent(tmp_path, dist):
    url = dist.publish(make_pack(tmp_path))
    res = em.install_from_distribution(consent=lambda e: False, index_url=url, health_check=ok_health)
    assert res.state == "CANCELLED" and em.active_pack() is None
    assert not list(em.downloads_dir().glob("*")) if em.downloads_dir().exists() else True
    assert dist.ranges == []  # the archive was never requested


# ------------------------------------------------------------------------------------------- offline / network
@pytest.mark.acceptance("ACC-ENGINE-002")
def test_offline_explains_then_install_from_file_works(tmp_path):
    with pytest.raises(AcetError) as ei:
        em.install_from_distribution(consent=lambda e: True, index_url="http://127.0.0.1:9/index.json")
    assert ei.value.data["reason"] == "NETWORK_UNAVAILABLE" and ei.value.code == "ACET-EPM-001"
    res = em.install_archive(make_pack(tmp_path), health_check=ok_health)
    assert res.state == "READY" and em.active_pack()["version"] == "1.0.0"


def test_explicit_network_errors(tmp_path, dist):
    url = dist.publish(make_pack(tmp_path))
    dist.status = 407
    with pytest.raises(AcetError) as ei:
        _install(url)
    assert ei.value.data["reason"] == "PROXY_REQUIRED"
    with pytest.raises(AcetError) as ei:
        em.fetch_index("http://example.com/index.json")  # plain HTTP to a remote host is refused
    assert ei.value.data["reason"] == "NO_DISTRIBUTION"
    with pytest.raises(AcetError) as ei:
        em.fetch_index(None)  # this build publishes no distribution yet
    assert ei.value.data["reason"] == "NO_DISTRIBUTION"


def test_interrupted_download_resumes(tmp_path, dist):
    archive = make_pack(tmp_path)
    url = dist.publish(archive)
    dist.cut_after = archive.stat().st_size // 2
    with pytest.raises(AcetError) as ei:
        _install(url)
    assert ei.value.data["reason"] == "DOWNLOAD_INTERRUPTED"
    assert len(list(em.downloads_dir().glob("*.part"))) == 1 and em.active_pack() is None
    res = _install(url)
    assert res.state == "READY"
    assert dist.ranges[-1] == f"bytes={archive.stat().st_size // 2}-"  # resumed, not restarted


def test_disk_space_checked_before_download(tmp_path, dist, monkeypatch):
    url = dist.publish(make_pack(tmp_path))
    monkeypatch.setattr(em.shutil, "disk_usage", lambda p: type("U", (), {"free": 1024})())
    with pytest.raises(AcetError) as ei:
        _install(url)
    assert ei.value.data["reason"] == "DISK_SPACE_INSUFFICIENT" and dist.ranges == []


def test_disk_full_during_extraction(tmp_path, monkeypatch):
    archive = make_pack(tmp_path)
    real_open = open

    def full(path, mode="r", *a, **k):  # type: ignore[no-untyped-def]
        if mode == "xb":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, mode, *a, **k)

    monkeypatch.setattr(em, "open", full, raising=False)
    with pytest.raises(AcetError) as ei:
        em.install_archive(archive, health_check=ok_health)
    assert ei.value.data["reason"] == "DISK_SPACE_INSUFFICIENT"
    assert _staging_empty() and em.active_pack() is None


# ------------------------------------------------------------------------------------------- integrity
@pytest.mark.acceptance("ACC-ENGINE-003")
def test_modified_byte_is_an_integrity_failure(tmp_path, dist):
    archive = make_pack(tmp_path)
    data = bytearray(archive.read_bytes())
    data[len(data) // 3] ^= 0xFF
    bad = tmp_path / "bad.acetengine"
    bad.write_bytes(bytes(data))
    with pytest.raises(AcetError) as ei:
        em.install_archive(bad, health_check=ok_health)
    assert ei.value.data["reason"] in ("INTEGRITY_FAILURE", "SIGNATURE_INVALID")
    assert em.active_pack() is None and _staging_empty()
    # Through the distribution, the published SHA-256 catches it before anything is opened.
    url = dist.publish(archive, sha=hashlib.sha256(b"something else").hexdigest())
    with pytest.raises(AcetError) as ei:
        _install(url)
    assert ei.value.data["reason"] == "HASH_MISMATCH" and em.active_pack() is None


def _rezip(src: Path, dest: Path, mutate: Any) -> Path:
    with zipfile.ZipFile(src) as z:
        items = [(i, z.read(i)) for i in z.infolist()]
    items = mutate(items)
    with zipfile.ZipFile(dest, "w") as z:
        for info, data in items:
            z.writestr(info, data)
    return dest


@pytest.mark.parametrize(
    "case",
    ["traversal", "absolute", "duplicate", "reserved", "extra_member", "bomb", "unsigned", "foreign_key"],
)
def test_hostile_archives_are_refused_before_extraction(tmp_path, case):
    archive = make_pack(tmp_path)
    if case == "foreign_key":
        bad = make_pack(tmp_path / "x", key=OTHER)
    elif case == "bomb":
        bad = tmp_path / "bomb.acetengine"
        with zipfile.ZipFile(archive) as z, zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as out:
            for i in z.infolist():
                out.writestr(i, z.read(i))
            out.writestr("ghidra/zeros.bin", b"\0" * (50 * 1024**2))
    else:

        def mutate(items):  # type: ignore[no-untyped-def]
            if case == "traversal":
                return [*items, (zipfile.ZipInfo("../../evil.txt"), b"x")]
            if case == "absolute":
                return [*items, (zipfile.ZipInfo("/etc/evil"), b"x")]
            if case == "duplicate":
                return [*items, (zipfile.ZipInfo(items[1][0].filename.upper()), b"x")]
            if case == "reserved":
                return [*items, (zipfile.ZipInfo("ghidra/CON.txt"), b"x")]
            if case == "extra_member":
                return [*items, (zipfile.ZipInfo("ghidra/unlisted.dll"), b"x")]
            return [it for it in items if it[0].filename != em.MANIFEST]  # unsigned

        bad = _rezip(archive, tmp_path / f"{case}.acetengine", mutate)
    with pytest.raises(AcetError) as ei:
        em.install_archive(bad, health_check=ok_health)
    assert ei.value.data["reason"] in ("INTEGRITY_FAILURE", "SIGNATURE_INVALID"), (case, ei.value)
    assert em.active_pack() is None and not (tmp_path / "evil.txt").exists()
    assert _staging_empty()


def test_index_signed_by_a_local_key_is_refused(tmp_path, dist):
    url = dist.publish(make_pack(tmp_path), key=OTHER)
    admin = tmp_path / "acet-home" / "config" / "trusted_keys.json"
    admin.parent.mkdir(parents=True, exist_ok=True)
    admin.write_text(json.dumps({"keys": [{"key_id": "rel2", "alg": "ed25519",
                                           "public_key": ed25519.public_key(OTHER).hex(), "purposes": ["engine-pack"]}]}))  # fmt: skip
    with pytest.raises(AcetError) as ei:
        _install(url)
    assert ei.value.data["reason"] == "SIGNATURE_INVALID"


# ------------------------------------------------------------------------------------------- cancel / rollback / crash
def test_cancel_keeps_the_previous_pack(tmp_path, dist):
    em.install_archive(make_pack(tmp_path, "1.0.0"), health_check=ok_health)
    url = dist.publish(make_pack(tmp_path, "1.1.0"))
    cancel = threading.Event()

    def progress(step: str, done: int, total: int | None, msg: str) -> None:
        if step == "extract":
            cancel.set()

    res = _install(url, cancel=cancel, progress=progress)
    assert res.state == "CANCELLED" and em.active_pack()["version"] == "1.0.0"
    assert _staging_empty() and not (engine_packs.packs_root() / "acet-engines-1.1.0").exists()
    assert "CANCELLED" in em.log_path().read_text()


@pytest.mark.acceptance("ACC-089")
def test_failed_health_check_keeps_the_previous_pack(tmp_path):
    em.install_archive(make_pack(tmp_path, "1.0.0"), health_check=ok_health)
    with pytest.raises(AcetError) as ei:
        em.install_archive(make_pack(tmp_path, "1.1.0"),
                           health_check=lambda d, m: {"verdict": "FAILED", "engine_mode": "live"})  # fmt: skip
    assert ei.value.data["reason"] == "HEALTH_CHECK_FAILED"
    assert em.active_pack()["version"] == "1.0.0"
    assert not (engine_packs.packs_root() / "acet-engines-1.1.0").exists()
    em.install_archive(make_pack(tmp_path, "1.2.0"), health_check=ok_health)
    assert em.active_pack()["version"] == "1.2.0"
    assert em.rollback()["active"] == "acet-engines-1.0.0" and em.active_pack()["version"] == "1.0.0"


@pytest.mark.acceptance("ACC-ENGINE-004")
def test_crash_during_extraction_is_recovered(tmp_path):
    em.install_archive(make_pack(tmp_path, "1.0.0"), health_check=ok_health)
    archive = make_pack(tmp_path, "2.0.0", extra={f"ghidra/blob{i}.bin": os.urandom(4096) for i in range(30)})
    code = (
        "import os, sys\n"
        "from acet.platform import engine_manager as em, signing\n"
        f"signing._bundled_store = lambda: {{'keys': [{json.dumps({'key_id': 'rel', 'alg': 'ed25519', 'public_key': ed25519.public_key(SECRET).hex(), 'purposes': ['engine-pack']})}]}}\n"
        "def p(step, done, total, msg):\n"
        "    if step == 'extract' and total and done > total // 2:\n"
        "        os._exit(9)  # the process dies mid-extraction (power loss, kill)\n"
        f"em.install_archive(__import__('pathlib').Path({str(archive)!r}), progress=p, health_check=lambda d, m: {{}})\n"
    )  # fmt: skip
    r = subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    assert r.returncode == 9
    assert not _staging_empty()  # the crash left a half-extracted staging tree
    assert em.active_pack()["version"] == "1.0.0"  # never considered installed
    rec = em.recover()
    assert rec["removed"] and _staging_empty()
    assert em.active_pack()["version"] == "1.0.0" and em.status()["pack"]["version"] == "1.0.0"
    assert "RECOVERED" in em.log_path().read_text()


def test_half_activated_pack_and_dangling_pointer_are_recovered(tmp_path):
    em.install_archive(make_pack(tmp_path, "1.0.0"), health_check=ok_health)
    em.install_archive(make_pack(tmp_path, "1.1.0"), health_check=ok_health)
    half = engine_packs.packs_root() / "acet-engines-9.9.9"
    half.mkdir()
    (half / em.INSTALLING_MARKER).write_text("x")
    import shutil

    shutil.rmtree(engine_packs.packs_root() / "acet-engines-1.1.0")  # active pack vanished
    rec = em.recover()
    assert "packs/acet-engines-9.9.9" in rec["removed"] and rec["restored_active"] == "acet-engines-1.0.0"
    assert em.active_pack()["version"] == "1.0.0"


# ------------------------------------------------------------------------------------------- verify / repair
def test_verify_and_repair_only_what_is_damaged(tmp_path):
    archive = make_pack(tmp_path)
    em.install_archive(archive, health_check=ok_health)
    assert em.verify_active()["state"] == "VERIFIED"
    act = Path(em.active_pack()["path"])
    (act / "runtime/java/release").write_text("tampered")
    (act / "ghidra/Ghidra/application.properties").unlink()
    v = em.verify_active()
    assert v["state"] == "REPAIR_REQUIRED" and set(v["bad_files"]) == {
        "runtime/java/release",
        "ghidra/Ghidra/application.properties",
    }
    assert em.status()["state"] == "REPAIR_REQUIRED"
    assert em.repair()["needs"] == "archive"  # no verified local copy: explicit, no guess
    r = em.repair(archive=archive, health_check=ok_health)
    assert r["state"] == "VERIFIED" and (act / "runtime/java/release").read_bytes() == b'JAVA_VERSION="21.0.5"\n'
    assert "REPAIRED" in em.log_path().read_text()


def test_ghidra_is_pinned_to_the_private_java(tmp_path):
    """Ghidra must start on the pack's runtime, not on a JDK from JAVA_HOME/PATH/~/.ghidra preferences."""
    archive = make_pack(tmp_path)
    em.install_archive(archive, health_check=ok_health)
    act = Path(em.active_pack()["path"])
    props = (act / "ghidra/support/launch.properties").read_text()
    home = (act / "runtime/java").resolve().as_posix()
    assert f"JAVA_HOME_OVERRIDE={home}\n" in props and "VMARGS=-Xshare:off" in props
    assert em.verify_active()["state"] == "VERIFIED"  # ACET's own pin is the only accepted difference
    (act / "ghidra/support/launch.properties").write_text(props.replace(home, "/usr/lib/jvm/evil"))
    v = em.verify_active()
    assert v["state"] == "REPAIR_REQUIRED" and v["bad_files"] == ["ghidra/support/launch.properties"]
    (act / "ghidra/support/launch.properties").write_text(props + "VMARGS=-javaagent:x.jar\n")
    assert em.verify_active()["state"] == "REPAIR_REQUIRED"  # any other change stays a tamper
    assert em.repair(archive=archive, health_check=ok_health)["state"] == "VERIFIED"
    assert (act / "ghidra/support/launch.properties").read_text() == props


def test_log_never_contains_credentials(tmp_path):
    log = em.InstallLog()
    log.write("DOWNLOAD_START", url="https://user:s3cret@mirror.example/p.acetengine?token=abc")
    text = em.log_path().read_text()
    assert "s3cret" not in text and "token=abc" not in text and "mirror.example/p.acetengine" in text


# ------------------------------------------------------------------------------------------- gating
@pytest.mark.acceptance("ACC-ENGINE-006")
def test_profile_gating_follows_health_checked_engines(tmp_path, monkeypatch):
    monkeypatch.setattr(em.shutil, "which", lambda name: None)  # no system Java at all
    st = em.status()
    assert st["state"] == "NOT_INSTALLED"
    assert {k: v["state"] for k, v in st["profiles"].items()} == {
        "FAST": "READY", "STANDARD": "UNAVAILABLE", "DEEP": "UNAVAILABLE", "RESEARCH": "UNAVAILABLE"}  # fmt: skip
    archive = make_pack(tmp_path)
    # A pack whose health check did not validate the engines: present on disk is not READY.
    em.install_archive(
        archive, health_check=lambda d, m: {"verdict": "PARTIAL", "engine_mode": "live", "providers": {}}
    )
    st = em.status()
    assert {c["id"]: c["state"] for c in st["components"]}["ghidra"] == "UNVERIFIED"
    assert st["profiles"]["STANDARD"]["state"] != "READY"
    assert em.profile_gate("STANDARD@1")["state"] != "READY"
    # After a validated health check: required engines READY; Ghidriff absent → STANDARD DEGRADED, not READY.
    em.verify_active(health=True, health_check=ok_health)
    st = em.status()
    comps = {c["id"]: c for c in st["components"]}
    assert comps["java"]["state"] == "READY" and comps["ghidra"]["state"] == "READY"
    assert comps["ghidriff"]["state"] == "MISSING" and comps["bindiff"]["state"] == "NOT_INSTALLED"
    assert comps["diaphora"]["state"] == "NOT_CONFIGURED" and comps["diaphora"]["role"] == "EXTERNAL"
    assert st["profiles"]["FAST"]["state"] == "READY" and st["profiles"]["STANDARD"]["state"] == "DEGRADED"
    assert st["profiles"]["STANDARD"]["missing_optional"] == ["ghidriff"]
    assert all(c["why"] for c in st["components"])


def test_ghidriff_version_found_in_venv_and_embedded_cpython_layouts(tmp_path):
    from acet.engines.environment import _venv_dist_version

    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "lib/python3.11/site-packages/ghidriff-1.0.0.dist-info").mkdir(parents=True)
    embed = tmp_path / "pack/ghidriff"  # Windows embeddable CPython: python.exe at the root
    (embed / "Lib/site-packages/ghidriff-1.0.0.dist-info").mkdir(parents=True)
    assert _venv_dist_version(str(venv / "bin/python"), "ghidriff") == "1.0.0"
    assert _venv_dist_version(str(embed / "python.exe"), "ghidriff") == "1.0.0"
    assert _venv_dist_version(str(embed / "python.exe"), "pyghidra") is None
