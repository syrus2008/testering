"""ACET Engine Pack Manager: detect, download, verify, install, repair, update, roll back (spec §46, §64, §65,
ACET-UPD-001/002/005, ACET-SUP-001..005, ACET-LIC-001; ADR-0011, ADR-0013).

The application (UI, Core, DB, import, FAST, reporting) never depends on a system Java, Ghidra or Python.
Advanced analysis engines come from a signed **Engine Pack** that this module manages under
``<ACET_HOME>/engines``::

    downloads/<archive>.acetengine[.part]    resumable downloads (verified before use)
    staging/<uuid>/                          extraction area, never active
    packs/<id>-<version>/                    immutable verified installations
    current.json                             atomic pointer {"active", "previous"}
    <ACET_HOME>/logs/engine-pack-install.log

Pipeline (nothing incomplete ever becomes active)::

    resolve signed index → consent → disk check → download → SHA-256 → archive safety
    → signed manifest (trust, schema, compatibility, licenses, revocation) → extract to staging
    (each file hashed while written) → verify extracted pack → move into packs/ → health check
    (the real ``doctor --full`` golden self-test against this pack) → verification record
    → atomic pointer switch (previous pack kept for rollback) → READY

A local file goes through exactly the same steps as a download. Detection is automatic; installation
is always explicit (consent).
"""

from __future__ import annotations

import errno
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

import acet
from acet.domain.error_codes import AcetError
from acet.domain.timeutil import utc_now_iso
from acet.platform import engine_packs
from acet.platform.paths import acet_home
from acet.platform.signing import load_trust_store, verify_envelope

ARCHIVE_SUFFIX = ".acetengine"
MANIFEST = "engine-pack.json"
INSTALLING_MARKER = ".acet-installing"
VERIFICATION_FILE = ".acet-verification.json"
DISK_MARGIN = 256 * 1024**2
CHUNK = 1 << 20
REASONS = {
    "NETWORK_UNAVAILABLE": "ACET-EPM-001",
    "TLS_ERROR": "ACET-EPM-002",
    "PROXY_REQUIRED": "ACET-EPM-003",
    "DOWNLOAD_INTERRUPTED": "ACET-EPM-004",
    "SIGNATURE_INVALID": "ACET-EPM-005",
    "HASH_MISMATCH": "ACET-EPM-006",
    "PACK_INCOMPATIBLE": "ACET-EPM-007",
    "DISK_SPACE_INSUFFICIENT": "ACET-EPM-008",
    "INTEGRITY_FAILURE": "ACET-EPM-009",
    "HEALTH_CHECK_FAILED": "ACET-EPM-010",
    "NO_DISTRIBUTION": "ACET-EPM-011",
    "REVOKED": "ACET-EPM-012",
}

Progress = Callable[[str, int, "int | None", str], None]  # step, done, total, message
HealthCheck = Callable[[Path, dict[str, Any]], dict[str, Any]]


def fail(reason: str, detail: str, **data: Any) -> AcetError:
    return AcetError(REASONS[reason], detail, data={"reason": reason, **data})


class Cancelled(Exception):
    """The user cancelled; staging was removed and the active pack is unchanged."""


def _noop_progress(step: str, done: int, total: int | None, message: str) -> None:
    pass


# --------------------------------------------------------------------------------------------- layout
def engines_root() -> Path:
    return acet_home() / "engines"


def downloads_dir() -> Path:
    return engines_root() / "downloads"


def staging_dir() -> Path:
    return engines_root() / "staging"


def pointer_path() -> Path:
    return engines_root() / "current.json"


def log_path() -> Path:
    return acet_home() / "logs" / "engine-pack-install.log"


class InstallLog:
    """Plain-text journal of every Engine Pack operation. URLs are logged without user info or query
    strings, so proxy credentials or signed-URL tokens never reach the log."""

    def __init__(self) -> None:
        log_path().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: str, **fields: Any) -> None:
        parts = [f"{k}={_redact(v)}" for k, v in sorted(fields.items()) if v is not None]
        line = f"{utc_now_iso()} {event} " + " ".join(parts)
        with self._lock, open(log_path(), "a", encoding="utf-8") as fh:
            fh.write(line.rstrip() + "\n")


def _redact(v: Any) -> str:
    s = str(v)
    if "://" in s:
        u = urllib.parse.urlsplit(s)
        host = u.hostname or ""
        if u.port:
            host += f":{u.port}"
        s = urllib.parse.urlunsplit((u.scheme, host, u.path, "", ""))
    return s.replace("\n", " ")


def _read_pointer() -> dict[str, Any]:
    try:
        data: dict[str, Any] = json.loads(pointer_path().read_text(encoding="utf-8"))
        return data
    except (OSError, ValueError):
        return {"active": None, "previous": None}


def _write_pointer(data: dict[str, Any]) -> None:
    pointer_path().parent.mkdir(parents=True, exist_ok=True)
    tmp = pointer_path().with_name(f"current.{uuid.uuid4().hex}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(data, indent=2))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, pointer_path())


def _pack_dir(name: str | None) -> Path | None:
    if not name:
        return None
    d = engine_packs.packs_root() / name
    return d if (d / MANIFEST).is_file() and not (d / INSTALLING_MARKER).exists() else None


def _manifest_of(d: Path) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((d / MANIFEST).read_text(encoding="utf-8"))["payload"]
    return payload


def verification_record(d: Path) -> dict[str, Any] | None:
    try:
        rec: dict[str, Any] = json.loads((d / VERIFICATION_FILE).read_text(encoding="utf-8"))
        return rec
    except (OSError, ValueError):
        return None


def active_pack() -> dict[str, Any] | None:
    """The active pack (pointer), with its manifest and last verification record; None if none is active."""
    d = _pack_dir(_read_pointer().get("active"))
    if d is None:
        return None
    m = _manifest_of(d)
    return {
        "id": m["id"],
        "version": m["version"],
        "path": str(d),
        "manifest": m,
        "verification": verification_record(d),
        "revoked": bool(engine_packs.is_revoked(m["id"], m["version"])),
    }


# --------------------------------------------------------------------------------------------- recovery
def recover(log: InstallLog | None = None) -> dict[str, Any]:
    """Run at start-up: incomplete installations are never mistaken for usable ones (ACC-ENGINE-004).
    Staging leftovers and half-activated packs are removed; a dangling pointer falls back to the previous
    pack. Partial downloads are kept (resumable) — they are verified by hash before any use."""
    log = log or InstallLog()
    removed: list[str] = []
    for d in sorted(staging_dir().iterdir()) if staging_dir().is_dir() else []:
        shutil.rmtree(d, ignore_errors=True)
        removed.append(f"staging/{d.name}")
    for d in sorted(engine_packs.packs_root().iterdir()) if engine_packs.packs_root().is_dir() else []:
        if (d / INSTALLING_MARKER).exists():
            shutil.rmtree(d, ignore_errors=True)
            removed.append(f"packs/{d.name}")
    ptr = _read_pointer()
    restored = None
    if ptr.get("active") and _pack_dir(ptr["active"]) is None:
        prev = ptr.get("previous") if _pack_dir(ptr.get("previous")) else None
        _write_pointer({"active": prev, "previous": None, "activated_at": utc_now_iso(), "recovered": True})
        restored = prev
    if removed or restored:
        log.write("RECOVERED", removed=",".join(removed) or None, restored_active=restored)
    return {"removed": removed, "restored_active": restored}


# --------------------------------------------------------------------------------------------- index
def _bundled_distribution() -> dict[str, Any]:
    cfg: dict[str, Any] = json.loads(
        (resources.files("acet.platform") / "distribution.json").read_text(encoding="utf-8")
    )
    return cfg


def distribution_config() -> dict[str, Any]:
    """Where the signed pack index is published. The URL grants no trust: the index must be signed by a
    key of the bundled trust store (ADR-0011); a developer/enterprise mirror can be named with
    ACET_ENGINE_INDEX_URL and is held to the same signature."""
    cfg = _bundled_distribution()
    extra = os.environ.get("ACET_ENGINE_INDEX_URL")
    if extra:
        cfg["index_urls"] = [extra, *cfg.get("index_urls", [])]
    return cfg


def _check_url(url: str) -> None:
    u = urllib.parse.urlsplit(url)
    loopback = u.hostname in ("127.0.0.1", "localhost", "::1")
    if u.scheme == "https" or u.scheme == "file" or (u.scheme == "http" and loopback):
        return
    raise fail("NO_DISTRIBUTION", f"refused URL scheme for {_redact(url)} (HTTPS required)")


def _open(url: str, *, offset: int = 0, timeout: float = 30.0) -> Any:
    _check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": f"ACET/{acet.__version__}"})
    if offset:
        req.add_header("Range", f"bytes={offset}-")
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 407:
            raise fail("PROXY_REQUIRED", f"proxy authentication required for {_redact(url)}") from exc
        if exc.code == 416 and offset:
            raise
        raise fail("NETWORK_UNAVAILABLE", f"HTTP {exc.code} for {_redact(url)}") from exc
    except urllib.error.URLError as exc:
        raise _net_error(exc.reason, url) from exc
    except (ssl.SSLError, ssl.CertificateError) as exc:
        raise fail("TLS_ERROR", f"{type(exc).__name__} for {_redact(url)}") from exc
    except (TimeoutError, OSError) as exc:
        raise _net_error(exc, url) from exc


def _net_error(reason: Any, url: str) -> AcetError:
    if isinstance(reason, ssl.SSLError | ssl.CertificateError):
        return fail("TLS_ERROR", f"{type(reason).__name__}: {reason} ({_redact(url)})")
    text = str(reason)
    if "407" in text or "Proxy Authentication" in text:
        return fail("PROXY_REQUIRED", f"proxy refused the connection ({_redact(url)})")
    if isinstance(reason, socket.gaierror | ConnectionRefusedError | TimeoutError | socket.timeout | OSError):
        return fail("NETWORK_UNAVAILABLE", f"{type(reason).__name__}: {text} ({_redact(url)})")
    return fail("NETWORK_UNAVAILABLE", f"{text} ({_redact(url)})")


def fetch_index(url: str | None = None) -> list[dict[str, Any]]:
    """Signed list of published packs. Fails closed: unsigned, untrusted or malformed → refused."""
    urls = [url] if url else list(distribution_config().get("index_urls") or [])
    if not urls:
        raise fail("NO_DISTRIBUTION", "no Engine Pack distribution is configured in this build")
    errors: list[AcetError] = []
    for u in urls:
        try:
            with _open(u) as resp:
                raw = resp.read(16 * 1024**2 + 1)
        except AcetError as exc:
            errors.append(exc)
            continue
        if len(raw) > 16 * 1024**2:
            raise fail("INTEGRITY_FAILURE", "index larger than 16 MiB")
        try:
            env = json.loads(raw)
            # Bundled store only: an index can only be vouched for by a key shipped with ACET.
            payload = verify_envelope(env, load_trust_store(local=False), purpose="engine-pack")
        except (ValueError, AcetError) as exc:
            raise fail("SIGNATURE_INVALID", f"engine pack index not signed by a trusted key ({exc})") from exc
        packs = payload.get("packs") if isinstance(payload, dict) else None
        if payload.get("kind") != "acet-engine-pack-index" or not isinstance(packs, list):
            raise fail("INTEGRITY_FAILURE", "malformed engine pack index")
        for p in packs:
            for k in ("id", "version", "supported_acet", "archive_url", "archive_sha256", "archive_size"):
                if k not in p:
                    raise fail("INTEGRITY_FAILURE", f"index entry without {k}")
        return [{**p, "_index_url": u} for p in packs]
    raise errors[0]


def current_platform() -> str:
    machine = platform.machine().lower()
    arch = "x64" if machine in ("amd64", "x86_64") else machine
    osname = "win" if sys.platform == "win32" else sys.platform
    return f"{osname}-{arch}"


def platform_matches(pack_platform: str | None) -> bool:
    return pack_platform in (None, "any") or pack_platform == current_platform()


def resolve_compatible(entries: list[dict[str, Any]]) -> dict[str, Any]:
    entries = [e for e in entries if platform_matches(e.get("platform"))]
    if not entries:
        raise fail("PACK_INCOMPATIBLE", f"no published pack is built for {current_platform()}")
    ok = [
        e
        for e in entries
        if engine_packs.version_in_range(acet.__version__, e["supported_acet"])
        and not engine_packs.is_revoked(e["id"], e["version"])
    ]
    if not ok:
        raise fail("PACK_INCOMPATIBLE", f"no published pack supports ACET {acet.__version__}")
    return max(ok, key=lambda e: engine_packs._vt(e["version"]))


def update_available(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    act = active_pack()
    try:
        best = resolve_compatible(entries)
    except AcetError:
        return None
    if act is None or (best["id"], engine_packs._vt(best["version"])) > (act["id"], engine_packs._vt(act["version"])):
        return best
    return None


# --------------------------------------------------------------------------------------------- download
def check_disk(path: Path, needed: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    if free < needed + DISK_MARGIN:
        raise fail(
            "DISK_SPACE_INSUFFICIENT",
            f"{needed + DISK_MARGIN} bytes needed (download + staging + installation), {free} free",
            needed=needed + DISK_MARGIN,
            free=free,
        )


def download(
    url: str,
    expected_sha256: str,
    expected_size: int,
    *,
    progress: Progress = _noop_progress,
    cancel: threading.Event | None = None,
    log: InstallLog | None = None,
) -> Path:
    """Download into downloads/; resumes a partial file when the server honours Range. The result is
    only returned after its size and SHA-256 match the signed index (HASH_MISMATCH otherwise)."""
    log = log or InstallLog()
    name = PurePosixPath(urllib.parse.urlsplit(url).path).name or "pack"
    final = downloads_dir() / f"{expected_sha256[:16]}-{name}"
    if final.is_file() and _sha256(final) == expected_sha256:
        progress("download", expected_size, expected_size, "already downloaded (verified)")
        return final
    part = final.with_name(final.name + ".part")
    downloads_dir().mkdir(parents=True, exist_ok=True)
    offset = part.stat().st_size if part.is_file() else 0
    if offset > expected_size:
        part.unlink()
        offset = 0
    log.write("DOWNLOAD_START", url=url, resume_from=offset or None, size=expected_size)
    try:
        resp = _open(url, offset=offset)
    except urllib.error.HTTPError:  # 416: our partial file is not resumable
        part.unlink(missing_ok=True)
        offset = 0
        resp = _open(url)
    with resp:
        status = getattr(resp, "status", 200)
        if offset and status != 206:  # server ignored Range: restart from scratch
            offset = 0
        mode = "ab" if offset else "wb"
        done = offset
        try:
            with open(part, mode) as fh:
                while True:
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    try:
                        chunk = resp.read(CHUNK)
                    except (http.client.IncompleteRead, OSError, TimeoutError) as exc:
                        raise fail("DOWNLOAD_INTERRUPTED", f"{type(exc).__name__} after {done} bytes") from exc
                    if not chunk:
                        break
                    fh.write(chunk)
                    done += len(chunk)
                    if done > expected_size:
                        raise fail("HASH_MISMATCH", "download larger than published size")
                    progress("download", done, expected_size, f"Downloading {name}")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise fail("DISK_SPACE_INSUFFICIENT", "disk full while downloading") from exc
            raise
    if done < expected_size:
        log.write("DOWNLOAD_INTERRUPTED", received=done, size=expected_size)
        raise fail("DOWNLOAD_INTERRUPTED", f"connection closed after {done} of {expected_size} bytes")
    progress("verify", 0, None, "Verifying download (SHA-256)")
    got = _sha256(part)
    if got != expected_sha256:
        part.unlink(missing_ok=True)
        log.write("HASH_MISMATCH", expected=expected_sha256, got=got)
        raise fail("HASH_MISMATCH", f"expected {expected_sha256}, got {got}")
    os.replace(part, final)
    log.write("DOWNLOAD_VERIFIED", sha256=got, size=done)
    return final


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------------------------- archive
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/$ ()+@")


def safe_member_name(name: str) -> bool:
    """Archive member names allowed in an Engine Pack: real engines contain '$', spaces and parentheses
    (Jython classes, Windows tools), so the rule targets what is dangerous instead: traversal, absolute or
    drive paths, backslashes, control characters, Windows device names, trailing dots/spaces."""
    if not name or set(name) - _ALLOWED or name.startswith("/"):
        return False
    for part in PurePosixPath(name).parts:
        if part in ("", ".", "..") or part != part.strip() or part.endswith("."):
            return False
        if part.split(".")[0].lower() in _RESERVED:
            return False
    return True


def archive_limits() -> Any:
    from acet.reporting.acetpack import ArchiveLimits

    return ArchiveLimits(
        max_entries=400_000, max_total_bytes=12 * 1024**3, max_entry_bytes=3 * 1024**3, max_ratio=400.0, max_depth=40
    )


def read_archive_manifest(archive: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Archive safety (before extraction) + signed manifest verification. Returns (manifest, envelope)."""
    from acet.reporting.acetpack import check_archive

    try:
        z = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise fail("INTEGRITY_FAILURE", f"not a valid Engine Pack archive ({type(exc).__name__})") from exc
    with z:
        try:
            check_archive(z, archive_limits(), require=(MANIFEST,), name_ok=safe_member_name)
        except AcetError as exc:
            raise fail("INTEGRITY_FAILURE", exc.detail or exc.spec.summary) from exc
        try:
            env = json.loads(z.read(MANIFEST))
        except (ValueError, KeyError, zipfile.BadZipFile, zlib.error, EOFError) as exc:
            raise fail("INTEGRITY_FAILURE", f"unreadable engine-pack.json ({type(exc).__name__})") from exc
        members = {i.filename for i in z.infolist() if not i.is_dir()} - {MANIFEST}
    try:
        manifest = engine_packs.verify_manifest(env)
    except AcetError as exc:
        if exc.code == "ACET-PACK-001":
            raise fail("SIGNATURE_INVALID", exc.detail or "untrusted signature") from exc
        if "revoked" in (exc.detail or ""):
            raise fail("REVOKED", exc.detail or "revoked") from exc
        raise fail("PACK_INCOMPATIBLE", exc.detail or exc.spec.summary) from exc
    if members != set(manifest["checksums"]):
        extra, missing = sorted(members - set(manifest["checksums"])), sorted(set(manifest["checksums"]) - members)
        raise fail("INTEGRITY_FAILURE", f"archive members differ from the signed manifest: +{extra[:3]} -{missing[:3]}")
    return manifest, env


def _extract(
    archive: Path, dest: Path, manifest: dict[str, Any], progress: Progress, cancel: threading.Event | None
) -> None:
    """Extract every member, hashing while writing; a byte that differs from the signed manifest aborts."""
    with zipfile.ZipFile(archive) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        total = sum(i.file_size for i in infos)
        done = 0
        for i in infos:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            target = dest / PurePosixPath(i.filename)
            if dest.resolve() not in target.resolve().parents and target.resolve() != dest.resolve():
                raise fail("INTEGRITY_FAILURE", f"member escapes staging: {i.filename[:80]}")
            target.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            written = 0
            try:
                with z.open(i) as src, open(target, "xb") as out:
                    while chunk := src.read(CHUNK):
                        written += len(chunk)
                        if written > i.file_size:
                            raise fail("INTEGRITY_FAILURE", f"member larger than declared: {i.filename[:80]}")
                        if i.filename != MANIFEST:
                            h.update(chunk)
                        out.write(chunk)
                        done += len(chunk)
                        progress("extract", done, total, f"Installing {PurePosixPath(i.filename).parts[0]}")
            except (zipfile.BadZipFile, zlib.error, EOFError) as exc:  # CRC error, truncated member
                raise fail("INTEGRITY_FAILURE", f"corrupted member {i.filename[:80]} ({type(exc).__name__})") from exc
            except OSError as exc:
                if exc.errno == errno.ENOSPC:
                    raise fail("DISK_SPACE_INSUFFICIENT", "disk full while extracting") from exc
                raise
            if i.filename != MANIFEST and h.hexdigest() != manifest["checksums"].get(i.filename):
                raise fail("INTEGRITY_FAILURE", f"file differs from the signed manifest: {i.filename[:80]}")
            mode = (i.external_attr >> 16) & 0o777
            if mode & 0o111:  # keep executables executable (java, ghidra launch scripts)
                os.chmod(target, stat.S_IMODE(os.stat(target).st_mode) | 0o755)


# --------------------------------------------------------------------------------------------- private Java
LAUNCH_PROPERTIES = "support/launch.properties"


def _ghidra_props(pack_dir: Path, manifest: dict[str, Any]) -> tuple[str, Path] | None:
    gh = next((p for p in manifest["providers"] if p["provider_id"] == "ghidra"), None)
    if gh is None or not (manifest.get("runtime") or {}).get("java"):
        return None
    rel = f"{gh['executable'].rstrip('/')}/{LAUNCH_PROPERTIES}"
    return rel, pack_dir / rel


def _java_home(pack_dir: Path, manifest: dict[str, Any]) -> Path:
    return Path(pack_dir / str(manifest["runtime"]["java"]["path"])).resolve()


_OVERRIDE = re.compile(rb"^JAVA_HOME_OVERRIDE=[^\r\n]*", re.MULTILINE)


def configure_private_java(pack_dir: Path, manifest: dict[str, Any]) -> None:
    """Make Ghidra start on the pack's own Java, explicitly: ``JAVA_HOME_OVERRIDE`` in its launch.properties
    takes precedence over any JDK saved in the user's Ghidra preferences, JAVA_HOME or PATH. This is the only
    line ACET writes inside a pack (bytes elsewhere untouched, line endings kept); verification accepts it only
    when it points to the pack's own runtime."""
    found = _ghidra_props(pack_dir, manifest)
    if found is None or not found[1].is_file():
        return
    path = found[1]
    line = b"JAVA_HOME_OVERRIDE=" + _java_home(pack_dir, manifest).as_posix().encode()  # '/' is valid on Windows
    data = path.read_bytes()
    if _OVERRIDE.search(data):
        data = _OVERRIDE.sub(lambda _m: line, data, count=1)
    else:
        data = data + (b"" if data.endswith(b"\n") or not data else b"\n") + line + b"\n"
    tmp = path.with_name(path.name + ".acet-tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def pack_integrity_problems(pack_dir: Path, manifest: dict[str, Any]) -> list[str]:
    """Files that differ from the signed manifest, allowing only ACET's own JAVA_HOME_OVERRIDE line."""
    bad = engine_packs.verify_files(pack_dir, manifest)
    found = _ghidra_props(pack_dir, manifest)
    if found and found[0] in bad and found[1].is_file():
        rel, path = found
        data = path.read_bytes()
        expected = b"JAVA_HOME_OVERRIDE=" + _java_home(pack_dir, manifest).as_posix().encode()
        lines = _OVERRIDE.findall(data)
        if lines == [expected]:
            candidates = (
                _OVERRIDE.sub(b"JAVA_HOME_OVERRIDE=", data, count=1),  # the signed file had an empty override
                data.replace(expected + b"\n", b"", 1),  # ACET appended the line
            )
            if any(hashlib.sha256(c).hexdigest() == manifest["checksums"][rel] for c in candidates):
                bad.remove(rel)
    return bad


# --------------------------------------------------------------------------------------------- health
def doctor_health_check(pack_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """The real ``acet doctor --full`` golden self-test, run against this pack's engines."""
    from acet.engines.environment import detect
    from acet.platform.selftest import run_self_test

    env = detect(
        engine_packs.provider_overrides({"path": str(pack_dir)}), pack_id=f"{manifest['id']}@{manifest['version']}"
    )
    st = run_self_test(env=env)
    providers = {
        k: {"available": v.available, "version": v.version, "verified": v.verified, "reason": v.reason}
        for k, v in env.providers.items()
    }
    return {"verdict": st["verdict"], "engine_mode": st["engine_mode"], "self_test": st, "providers": providers}


# --------------------------------------------------------------------------------------------- install
@dataclass
class InstallResult:
    state: str  # READY | CANCELLED
    pack: str | None = None
    previous: str | None = None
    verification: dict[str, Any] | None = None
    steps: list[str] = field(default_factory=list)


def install_archive(
    archive: Path,
    *,
    expected_sha256: str | None = None,
    source: str = "file",
    progress: Progress = _noop_progress,
    cancel: threading.Event | None = None,
    health_check: HealthCheck | None = None,
    log: InstallLog | None = None,
) -> InstallResult:
    """Install a downloaded or local archive. Same validations whatever the source."""
    log = log or InstallLog()
    health_check = health_check or doctor_health_check
    res = InstallResult(state="FAILED")
    stage: Path | None = None
    final: Path | None = None
    try:
        progress("verify", 0, None, "Verifying package")
        res.steps.append("VERIFYING")
        archive_sha = _sha256(archive)
        if expected_sha256 is not None and archive_sha != expected_sha256:
            raise fail("HASH_MISMATCH", "archive differs from the published SHA-256")
        manifest, _env = read_archive_manifest(archive)
        name = f"{manifest['id']}-{manifest['version']}"
        log.write("INSTALL_START", pack=f"{manifest['id']}@{manifest['version']}", source=source,
                  archive_sha256=archive_sha)  # fmt: skip
        if not platform_matches(manifest.get("platform")):
            raise fail(
                "PACK_INCOMPATIBLE", f"{name} is built for {manifest.get('platform')}, this is {current_platform()}"
            )
        with zipfile.ZipFile(archive) as z:
            installed = int(manifest.get("installed_size") or sum(i.file_size for i in z.infolist()))
        check_disk(engines_root(), installed * 2)  # staging + the move is a rename (same volume)
        stage = staging_dir() / uuid.uuid4().hex[:12]  # short: Windows MAX_PATH with deep engine trees
        stage.mkdir(parents=True)
        (stage / INSTALLING_MARKER).write_text(utc_now_iso(), encoding="utf-8")
        res.steps.append("EXTRACTING")
        _extract(archive, stage, manifest, progress, cancel)
        progress("verify", 0, None, "Verifying installation")
        res.steps.append("VALIDATING")
        bad = engine_packs.verify_files(stage, manifest)
        if bad:
            raise fail("INTEGRITY_FAILURE", f"extracted files differ from the manifest: {bad[:3]}")
        for p in manifest["providers"]:
            if p["license_mode"] == "bundled" and not (stage / p["executable"]).exists():
                raise fail("INTEGRITY_FAILURE", f"{p['provider_id']} executable missing: {p['executable']}")
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        final = engine_packs.packs_root() / name
        if final.exists():
            if _pack_dir(name) is not None and _read_pointer().get("active") == name:
                shutil.rmtree(stage, ignore_errors=True)
                stage = None
                raise fail("INTEGRITY_FAILURE", f"{name} is already the active pack; use Verify or Repair")
            shutil.rmtree(final)  # an inactive leftover of the same version: replace it
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(stage, final)  # still carries INSTALLING_MARKER: not usable, removed by recover()
        stage = None
        configure_private_java(final, manifest)
        progress("health", 0, None, "Running engine diagnostics")
        res.steps.append("HEALTH_CHECK")
        health = health_check(final, manifest)
        log.write("HEALTH_CHECK", pack=name, verdict=health.get("verdict"), engines=health.get("engine_mode"))
        if health.get("verdict") == "FAILED" or health.get("engine_mode") == "none":
            raise fail(
                "HEALTH_CHECK_FAILED", f"self-test verdict {health.get('verdict')} ({health.get('engine_mode')})"
            )
        changed = pack_integrity_problems(final, manifest)  # running the engines must not alter the pack
        if changed:
            raise fail("HEALTH_CHECK_FAILED", "the engines modified their own installation: " + ", ".join(changed[:5]))
        record = {
            "pack": f"{manifest['id']}@{manifest['version']}",
            "verified_at": utc_now_iso(),
            "acet_version": acet.__version__,
            "verdict": health.get("verdict"),
            "health": health,
            "source": source,
        }
        (final / VERIFICATION_FILE).write_text(json.dumps(record, indent=2), encoding="utf-8")
        (final / INSTALLING_MARKER).unlink()
        prev = _read_pointer().get("active")
        _write_pointer({"active": name, "previous": prev if prev != name else None, "activated_at": utc_now_iso()})
        res.steps.append("ACTIVATED")
        log.write("ACTIVATED", pack=name, previous=prev)
        progress("done", 1, 1, "READY")
        res.state, res.pack, res.previous, res.verification = "READY", name, prev, record
        return res
    except Cancelled:
        log.write("CANCELLED", steps=",".join(res.steps))
        res.state = "CANCELLED"
        return res
    except AcetError as exc:
        log.write("FAILED", reason=exc.data.get("reason"), code=exc.code, detail=exc.detail)
        raise
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        if final is not None and (final / INSTALLING_MARKER).exists():
            shutil.rmtree(final, ignore_errors=True)  # never leave a half-activated pack behind


def resolve_from_distribution(index_url: str | None = None) -> dict[str, Any]:
    """The compatible pack of the signed index (what the consent dialog shows: version, sizes, components,
    licenses). Network only, nothing is downloaded."""
    entry = resolve_compatible(fetch_index(index_url))
    InstallLog().write("RESOLVED", pack=f"{entry['id']}@{entry['version']}", index=entry["_index_url"])
    return entry


def install_entry(
    entry: dict[str, Any],
    *,
    progress: Progress = _noop_progress,
    cancel: threading.Event | None = None,
    health_check: HealthCheck | None = None,
) -> InstallResult:
    """Download (after consent) and install a resolved index entry."""
    log = InstallLog()
    check_disk(
        engines_root(), int(entry["archive_size"]) + 2 * int(entry.get("installed_size") or entry["archive_size"])
    )
    try:
        archive = download(
            entry["archive_url"], entry["archive_sha256"], int(entry["archive_size"]), progress=progress, cancel=cancel,
            log=log,
        )  # fmt: skip
    except Cancelled:
        log.write("CANCELLED", step="download")
        return InstallResult(state="CANCELLED")
    return install_archive(
        archive, expected_sha256=entry["archive_sha256"], source=entry["_index_url"], progress=progress,
        cancel=cancel, health_check=health_check, log=log,
    )  # fmt: skip


def install_from_distribution(
    *,
    consent: Callable[[dict[str, Any]], bool],
    index_url: str | None = None,
    progress: Progress = _noop_progress,
    cancel: threading.Event | None = None,
    health_check: HealthCheck | None = None,
) -> InstallResult:
    """Resolve the compatible signed pack, ask for consent (size, components, licenses), then download and
    install it. Nothing is downloaded before ``consent`` returns True."""
    progress("resolve", 0, None, "Resolving the compatible Engine Pack")
    entry = resolve_from_distribution(index_url)
    if not consent(entry):
        InstallLog().write("CANCELLED", step="consent")
        return InstallResult(state="CANCELLED")
    return install_entry(entry, progress=progress, cancel=cancel, health_check=health_check)


# --------------------------------------------------------------------------------------------- verify / repair
def verify_active(*, health: bool = False, health_check: HealthCheck | None = None) -> dict[str, Any]:
    """Signature, manifest, compatibility, every file's SHA-256, expected executables, private Java; with
    ``health`` also the real self-test. Updates the verification record."""
    log = InstallLog()
    act = active_pack()
    if act is None:
        return {"state": "NOT_INSTALLED", "problems": []}
    d = Path(act["path"])
    problems: list[str] = []
    try:
        manifest = engine_packs.verify_manifest(json.loads((d / MANIFEST).read_text(encoding="utf-8")))
    except (AcetError, ValueError) as exc:
        log.write("VERIFY", pack=d.name, result="CORRUPTED", detail=str(exc))
        return {"state": "CORRUPTED", "problems": [f"manifest: {exc}"], "bad_files": []}
    bad = pack_integrity_problems(d, manifest)
    problems += [f"file missing or modified: {b}" for b in bad[:20]]
    for p in manifest["providers"]:
        if p["license_mode"] == "bundled" and not (d / p["executable"]).exists():
            problems.append(f"{p['provider_id']} executable missing")
    java = (manifest.get("runtime") or {}).get("java")
    if java and not _java_exe(d / java["path"]).is_file():
        problems.append("private Java runtime missing")
    record = verification_record(d) or {}
    if not problems and health:
        h = (health_check or doctor_health_check)(d, manifest)
        record = {**record, "verdict": h.get("verdict"), "health": h, "verified_at": utc_now_iso()}
        if h.get("verdict") == "FAILED":
            problems.append(f"health check verdict FAILED ({h.get('engine_mode')})")
        problems += [f"modified by the health check: {b}" for b in pack_integrity_problems(d, manifest)[:20]]
    elif not problems:
        record = {**record, "files_verified_at": utc_now_iso()}
    state = "VERIFIED" if not problems else "REPAIR_REQUIRED"
    record["last_verify"] = {"at": utc_now_iso(), "state": state, "problems": problems[:20]}
    (d / VERIFICATION_FILE).write_text(json.dumps(record, indent=2), encoding="utf-8")
    log.write("VERIFY", pack=d.name, result=state, bad_files=len(bad))
    return {"state": state, "problems": problems, "bad_files": bad, "pack": d.name}


def repair(
    *,
    archive: Path | None = None,
    progress: Progress = _noop_progress,
    cancel: threading.Event | None = None,
    health_check: HealthCheck | None = None,
) -> dict[str, Any]:
    """Restore only the damaged files from a verified archive of the *same* pack (cached download or a file the
    user selects); every restored file is hashed against the signed manifest before it replaces anything.
    Without a usable archive the answer is an explicit reinstall, never a guess."""
    log = InstallLog()
    v = verify_active()
    if v["state"] in ("NOT_INSTALLED", "VERIFIED"):
        return v
    act = active_pack()
    assert act is not None
    d = Path(act["path"])
    candidates = (
        [archive] if archive else sorted(downloads_dir().glob(f"*{ARCHIVE_SUFFIX}")) if downloads_dir().is_dir() else []
    )
    for cand in candidates:
        try:
            manifest, _ = read_archive_manifest(cand)
        except AcetError:
            continue
        if (manifest["id"], manifest["version"]) != (act["id"], act["version"]) or manifest != act["manifest"]:
            continue
        restore = v.get("bad_files") or list(manifest["checksums"])
        tmp = staging_dir() / f"repair-{uuid.uuid4().hex}"
        tmp.mkdir(parents=True)
        try:
            with zipfile.ZipFile(cand) as z:
                for n, rel in enumerate(restore):
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    out = tmp / rel
                    out.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        with z.open(rel) as src, open(out, "wb") as fh:
                            shutil.copyfileobj(src, fh, CHUNK)
                    except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
                        raise fail("INTEGRITY_FAILURE", f"repair source corrupted: {rel}") from exc
                    if _sha256(out) != manifest["checksums"][rel]:
                        raise fail("INTEGRITY_FAILURE", f"repair source differs from manifest: {rel}")
                    progress("repair", n + 1, len(restore), f"Restoring {rel}")
            for rel in restore:
                (d / rel).parent.mkdir(parents=True, exist_ok=True)
                os.replace(tmp / rel, d / rel)
        except Cancelled:
            return {"state": "CANCELLED"}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        configure_private_java(d, manifest)
        log.write("REPAIRED", pack=d.name, files=len(restore))
        return verify_active(health=True, health_check=health_check)
    log.write("REPAIR_NEEDS_SOURCE", pack=d.name)
    return {**v, "state": "REPAIR_REQUIRED", "needs": "archive",
            "message": "No verified copy of this pack is available locally: reinstall it (Install Engine Pack) "
                       "or select its archive (Install from file…)."}  # fmt: skip


def rollback() -> dict[str, Any]:
    """Re-activate the previous pack (explicit user action)."""
    ptr = _read_pointer()
    prev = ptr.get("previous")
    if not _pack_dir(prev):
        raise fail("INTEGRITY_FAILURE", "no previous Engine Pack is available")
    _write_pointer({"active": prev, "previous": ptr.get("active"), "activated_at": utc_now_iso()})
    InstallLog().write("ROLLBACK", active=prev, previous=ptr.get("active"))
    return {"active": prev}


def _java_exe(java_home: Path) -> Path:
    return java_home / "bin" / ("java.exe" if os.name == "nt" else "java")


def java_version(java_home: Path) -> str | None:
    """JDK version from its ``release`` file (no process is started)."""
    try:
        for line in (java_home / "release").read_text(encoding="utf-8").splitlines():
            if line.startswith("JAVA_VERSION="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        return None
    return None


# --------------------------------------------------------------------------------------------- readiness
COMPONENTS: list[dict[str, Any]] = [
    {
        "id": "java",
        "label": "Java Runtime",
        "role": "REQUIRED",
        "needed_by": ["STANDARD", "DEEP", "RESEARCH"],
        "why": "Ghidra runs on Java. ACET uses the Engine Pack's private Java runtime; no system Java, JAVA_HOME "
        "or PATH change is needed.",
    },
    {
        "id": "ghidra",
        "label": "Ghidra",
        "role": "REQUIRED",
        "needed_by": ["STANDARD", "DEEP", "RESEARCH"],
        "why": "Ghidra performs the static code analysis (disassembly, function extraction) required by the STANDARD "
        "profile and above.",
    },
    {
        "id": "ghidriff",
        "label": "Ghidriff",
        "role": "REQUIRED",
        "needed_by": ["STANDARD", "DEEP", "RESEARCH"],
        "why": "Ghidriff adds an independent function-diff evidence family. Without it STANDARD still runs but is "
        "reported PARTIAL (missing evidence).",
    },
    {
        "id": "binexport",
        "label": "BinExport",
        "role": "OPTIONAL",
        "needed_by": ["DEEP", "RESEARCH"],
        "why": "Exports Ghidra's analysis for BinDiff (DEEP profile).",
    },
    {
        "id": "bindiff",
        "label": "BinDiff",
        "role": "OPTIONAL",
        "needed_by": ["DEEP", "RESEARCH"],
        "why": "A third structural diff engine used by the DEEP profile.",
    },
    {
        "id": "qbindiff",
        "label": "QBinDiff",
        "role": "OPTIONAL",
        "needed_by": ["DEEP", "RESEARCH"],
        "why": "Experimental programmable diff used by the DEEP profile.",
    },
    {
        "id": "diaphora",
        "label": "Diaphora",
        "role": "EXTERNAL",
        "needed_by": [],
        "why": "Requires IDA Pro (proprietary) and is AGPL: it is never redistributed by ACET. Configure it "
        "separately if you own IDA (ADR-0009).",
    },
]
PROFILES = ("FAST", "STANDARD", "DEEP", "RESEARCH")


def _profile_providers(name: str) -> tuple[set[str], set[str]]:
    from acet.analysis.registry import OPTIONAL_PROCESSORS, PROCESSORS, get_profile

    prof = get_profile(f"{name}@1")
    req: set[str] = set()
    opt: set[str] = set()
    for proc in prof.processors:
        spec = PROCESSORS[proc]
        if spec.provider:
            (opt if proc in OPTIONAL_PROCESSORS else req).add(spec.provider)
    if "ghidra" in req:
        req.add("java")
    return req, opt


def engine_environment() -> Any:
    """Engines of the active Engine Pack (private Java included); local detection when no pack is active."""
    from acet.engines.environment import detect

    act = active_pack()
    if act is None:
        return detect()
    return detect(engine_packs.provider_overrides(act), pack_id=f"{act['id']}@{act['version']}")


def status(env: Any = None) -> dict[str, Any]:
    """What the UI, doctor and gating show. A component is READY only if it is detected *and* the last real
    health check of the active pack validated it — a folder that merely exists is never READY."""
    act = active_pack()
    if env is None:
        env = engine_environment()
    rec = (act or {}).get("verification") or {}
    last = rec.get("last_verify") or {}
    health_ok = bool(act) and rec.get("verdict") in ("VERIFIED", "PARTIAL") and last.get("state") != "REPAIR_REQUIRED"
    healthy = {k for k, v in ((rec.get("health") or {}).get("providers") or {}).items() if v.get("available")}
    pack_providers = {p["provider_id"] for p in ((act or {}).get("manifest") or {}).get("providers", [])}
    if act and ((act.get("manifest") or {}).get("runtime") or {}).get("java"):
        pack_providers.add("java")
    developer = act is None and any(
        p.available and not p.extra.get("replay") for k, p in env.providers.items() if k not in ("acet",)
    )

    def comp_state(cid: str) -> str:
        info = env.providers.get(cid)
        available = bool(info and info.available)
        if info is not None and info.extra.get("replay"):
            return "UNVERIFIED"  # golden replay (CI/tests): usable, never a verified live engine
        if cid == "diaphora":
            return "NOT_CONFIGURED"
        if act and cid in pack_providers:
            if not available:
                return "MISSING"
            return "READY" if health_ok and cid in healthy else "UNVERIFIED"
        if available:
            return "UNVERIFIED"  # developer configuration: detected, never health-checked by ACET
        return "MISSING" if next(c for c in COMPONENTS if c["id"] == cid)["role"] == "REQUIRED" else "NOT_INSTALLED"

    components = []
    for c in COMPONENTS:
        info = env.providers.get(c["id"])
        components.append(
            {
                **c,
                "state": comp_state(c["id"]),
                "version": info.version if info else None,
                "source": (info.extra.get("source") if info else None)
                or ("engine-pack" if c["id"] in pack_providers else None),
            }
        )
    by_id = {c["id"]: c["state"] for c in components}
    profiles = {}
    for name in PROFILES:
        req, opt = _profile_providers(name)
        missing_req = sorted(p for p in req if by_id.get(p) not in ("READY", "UNVERIFIED"))
        missing_opt = sorted(p for p in opt if by_id.get(p) not in ("READY", "UNVERIFIED"))
        unverified = sorted(p for p in req | opt if by_id.get(p) == "UNVERIFIED")
        state = "UNAVAILABLE" if missing_req else "DEGRADED" if missing_opt else "READY"
        if state == "READY" and unverified:
            state = "UNVERIFIED"
        profiles[name] = {"state": state, "missing_required": missing_req, "missing_optional": missing_opt,
                          "unverified": unverified}  # fmt: skip
    if act is None:
        overall = "DEVELOPER" if developer else "NOT_INSTALLED"
    elif act["revoked"]:
        overall = "REVOKED"
    elif last.get("state") == "REPAIR_REQUIRED":
        overall = "REPAIR_REQUIRED"
    elif not health_ok:
        overall = "UNVERIFIED"
    else:
        overall = "READY" if profiles["STANDARD"]["state"] == "READY" else "DEGRADED"
    if overall == "NOT_INSTALLED" or (overall == "DEVELOPER" and profiles["STANDARD"]["state"] == "UNAVAILABLE"):
        overall = "DEGRADED" if overall == "DEVELOPER" else overall
    return {
        "state": overall,
        "pack": {k: act[k] for k in ("id", "version", "path")} if act else None,
        "install_location": str(engines_root()),
        "verification": {k: rec.get(k) for k in ("verdict", "verified_at", "files_verified_at", "last_verify")}
        if act
        else None,
        "components": components,
        "profiles": profiles,
        "log": str(log_path()),
    }


def profile_gate(profile_ref: str, env: Any = None) -> dict[str, Any]:
    """Can this profile run as requested? Used before starting an analysis (UI / CLI)."""
    name = profile_ref.split("@", 1)[0]
    st = status(env)
    p = st["profiles"].get(name) or {"state": "READY", "missing_required": [], "missing_optional": []}
    return {"profile": profile_ref, **p, "engine_state": st["state"]}
