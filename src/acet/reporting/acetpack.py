"""`.acetpack` export / import (spec §43, ACET-EXP-001/002, ACET-ARC-001..003, ACET-FMT-001/002, ACET-SEC-003).

Layout: manifest.json, schema/, metadata/*.jsonl, results/*.jsonl, results/derived/**,
annotations/*.jsonl, artifacts/<sha256> (opt-in), checksums.txt.

Import is untrusted until proven otherwise: archive limits and path safety are
checked from the central directory before reading any member; every checksum is
verified before any write; rows are committed in one transaction with deferred
foreign keys; existing rows are never overwritten (IDs are preserved).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import acet
from acet.application.workspace import Workspace
from acet.domain.canonical import stable_json
from acet.domain.error_codes import AcetError
from acet.domain.jsonschema import SchemaValidationError, schema_dir, validate_named
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo

PACK_SCHEMA_VERSION = 1

METADATA_TABLES = [
    "product",
    "release",
    "build",
    "observation",
    "component",
    "artifact",
    "component_artifact",
    "role_assertion",
]
RESULT_TABLES = [
    "analysis_profile",
    "engine_pack",
    "analysis_run",
    "processor_run",
    "derived_result",
    "derived_input",
    "function_instance",
    "matcher_result",
    "consensus_match",
    "lineage",
    "lineage_assignment",
    "lineage_link",
    "detected_change",
    "external_event",
    "baseline_observation",
    "calibration_profile",
    "human_assertion",
]
ANNOTATION_TABLES = ["annotation"]
EXCLUDED_COLUMNS = {"product": {"workspace_id"}}  # re-bound to the target workspace on import


@dataclass(frozen=True)
class ArchiveLimits:
    max_entries: int = 200_000
    max_total_bytes: int = 8 * 1024**3
    max_entry_bytes: int = 2 * 1024**3
    max_ratio: float = 200.0
    max_depth: int = 24
    max_name: int = 400


def _pk(table: str, cols: list[str]) -> list[str]:
    for k in ("id", "sha256"):
        if k in cols:
            return [k]
    return cols


def _rows(ws: Workspace, table: str) -> list[dict[str, Any]]:
    cur = ws.db.conn.execute(f"SELECT * FROM {table}")
    cols = [d[0] for d in cur.description]
    drop = EXCLUDED_COLUMNS.get(table, set())
    rows = [{c: r[c] for c in cols if c not in drop} for r in cur.fetchall()]
    keys = _pk(table, [c for c in cols if c not in drop])
    return sorted(rows, key=lambda r: tuple(str(r[k]) for k in keys))


def _jsonl(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(stable_json(r) + b"\n" for r in rows)


def create_pack(ws: Workspace, dest: Path, *, include_artifacts: bool = False) -> Path:
    """Export the workspace. Artifact bytes are included only on explicit request (ACET-EXP-001)."""
    files: dict[str, bytes | Path] = {}
    for name in sorted(os.listdir(schema_dir())):
        files[f"schema/{name}"] = schema_dir() / name
    for t in METADATA_TABLES:
        files[f"metadata/{t}.jsonl"] = _jsonl(_rows(ws, t))
    for t in RESULT_TABLES:
        files[f"results/{t}.jsonl"] = _jsonl(_rows(ws, t))
    for t in ANNOTATION_TABLES:
        files[f"annotations/{t}.jsonl"] = _jsonl(_rows(ws, t))
    for (rel,) in ws.db.conn.execute("SELECT output_relpath FROM derived_result ORDER BY output_relpath"):
        base = ws.path / rel
        if base.is_dir():
            for p in sorted(base.rglob("*")):
                if p.is_file():
                    files[f"results/{p.relative_to(ws.path).as_posix()}"] = p
    if include_artifacts:
        for (sha,) in ws.db.conn.execute(
            "SELECT sha256 FROM artifact WHERE integrity_state='AVAILABLE' ORDER BY sha256"
        ):
            files[f"artifacts/{sha}"] = ws.store.path_for(sha)

    def data_of(v: bytes | Path) -> bytes:
        return v if isinstance(v, bytes) else v.read_bytes()

    entries = []
    for path, v in sorted(files.items()):
        b = data_of(v)
        entries.append({"path": path, "sha256": hashlib.sha256(b).hexdigest(), "size_bytes": len(b)})
    manifest = {
        "schema_version": PACK_SCHEMA_VERSION,
        "created_at": utc_now_iso(),
        "acet_version": acet.__version__,
        "workspace_id": ws.id or None,
        "includes_artifacts": include_artifacts,
        "files": entries,
    }
    if manifest["workspace_id"] is None:
        manifest.pop("workspace_id")
    validate_named(manifest, "acetpack-manifest")
    mbytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    checks = "".join(f"{e['sha256']}  {e['path']}\n" for e in entries)
    checks += f"{hashlib.sha256(mbytes).hexdigest()}  manifest.json\n"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", mbytes)
        for path, v in sorted(files.items()):
            z.writestr(path, data_of(v))
        z.writestr("checksums.txt", checks)
    os.replace(tmp, dest)
    with ws.db.transaction() as tx:
        repo.audit(tx, "pack.create", None, None, {"files": len(entries), "include_artifacts": include_artifacts})
    return dest


_SAFE = re.compile(r"^[A-Za-z0-9._\-/]+$")


def check_archive(
    z: zipfile.ZipFile, limits: ArchiveLimits, *, require: tuple[str, ...] = ("manifest.json", "checksums.txt")
) -> None:
    """ACET-ARC-001 / ACET-FS-001: reject before extraction; nothing is written on failure."""
    infos = z.infolist()
    if len(infos) > limits.max_entries:
        raise AcetError("ACET-SEC-002", f"too many entries ({len(infos)})")
    total = 0
    seen: set[str] = set()
    for i in infos:
        name = i.filename
        p = PurePosixPath(name)
        if (
            name.startswith(("/", "\\"))
            or "\\" in name
            or ":" in name
            or ".." in p.parts
            or not name
            or not _SAFE.match(name)
            or len(name) > limits.max_name
            or len(p.parts) > limits.max_depth
        ):
            raise AcetError("ACET-SEC-001", f"unsafe path in archive: {name[:80]!r}")
        if i.flag_bits & 0x1:
            # ACET-ARC-003: no password guessing; encrypted members need an explicit user-supplied password
            raise AcetError("ACET-SEC-001", f"encrypted entry (password required, never guessed): {name[:80]!r}")
        if stat.S_ISLNK(i.external_attr >> 16):
            raise AcetError("ACET-SEC-001", f"symbolic link in archive: {name[:80]!r}")
        if name.lower() in seen:
            raise AcetError("ACET-SEC-001", f"duplicate entry: {name[:80]!r}")
        seen.add(name.lower())
        if i.file_size > limits.max_entry_bytes:
            raise AcetError("ACET-SEC-002", f"entry too large: {name[:80]!r}")
        if i.compress_size and i.file_size / i.compress_size > limits.max_ratio:
            raise AcetError("ACET-SEC-002", f"compression ratio too high: {name[:80]!r}")
        total += i.file_size
        if total > limits.max_total_bytes:
            raise AcetError("ACET-SEC-002", "total uncompressed size exceeds limit")
    missing = [r for r in require if r not in seen]
    if missing:
        raise AcetError("ACET-PACK-001", f"required member(s) missing: {missing}")


def _read_bounded(z: zipfile.ZipFile, name: str, limit: int) -> bytes:
    with z.open(name) as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise AcetError("ACET-SEC-002", f"entry larger than declared: {name}")
    return data


def import_pack(ws: Workspace, pack: Path, *, limits: ArchiveLimits | None = None) -> dict[str, Any]:
    ws.require_writable()
    limits = limits or ArchiveLimits()
    with zipfile.ZipFile(pack) as z:
        check_archive(z, limits)
        infos = {i.filename: i for i in z.infolist()}
        try:
            manifest = json.loads(_read_bounded(z, "manifest.json", 64 * 1024**2))
        except json.JSONDecodeError as exc:
            raise AcetError("ACET-PACK-001", "manifest is not JSON") from exc
        if (
            isinstance(manifest, dict)
            and isinstance(manifest.get("schema_version"), int)
            and manifest["schema_version"] > PACK_SCHEMA_VERSION
        ):
            raise AcetError("ACET-PACK-002", f"pack schema v{manifest['schema_version']} > v{PACK_SCHEMA_VERSION}")
        try:
            validate_named(manifest, "acetpack-manifest")
        except SchemaValidationError as exc:
            raise AcetError("ACET-PACK-001", f"invalid manifest: {exc}") from exc
        checks: dict[str, str] = {}
        for line in _read_bounded(z, "checksums.txt", 64 * 1024**2).decode("utf-8").splitlines():
            sha, _, name = line.partition("  ")
            checks[name] = sha
        declared = {e["path"]: e for e in manifest["files"]}
        members = set(infos) - {"manifest.json", "checksums.txt"}
        if members != set(declared) or set(checks) != set(declared) | {"manifest.json"}:
            raise AcetError("ACET-PACK-001", "archive members do not match manifest/checksums")
        for name, e in declared.items():
            if infos[name].file_size != e["size_bytes"]:
                raise AcetError("ACET-PACK-001", f"size differs from manifest: {name}")
        if hashlib.sha256(_read_bounded(z, "manifest.json", 64 * 1024**2)).hexdigest() != checks["manifest.json"]:
            raise AcetError("ACET-PACK-001", "manifest checksum mismatch")
        stage = Path(tempfile.mkdtemp(prefix="acetpack-", dir=ws.path / "temp"))
        try:
            for name, e in sorted(declared.items()):
                data = _read_bounded(z, name, e["size_bytes"])
                if (
                    len(data) != e["size_bytes"]
                    or hashlib.sha256(data).hexdigest() != e["sha256"]
                    or checks[name] != e["sha256"]
                ):
                    raise AcetError("ACET-PACK-001", f"checksum mismatch: {name}")
                out = stage / name
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
            manifest["_archive_sha256"] = hashlib.sha256(pack.read_bytes()).hexdigest()
            return _commit(ws, stage, manifest)
        finally:
            shutil.rmtree(stage, ignore_errors=True)


def _load(stage: Path, rel: str) -> list[dict[str, Any]]:
    p = stage / rel
    if not p.is_file():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def _commit(ws: Workspace, stage: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    stats: dict[str, int] = {}
    derived_repaired = 0
    # Bytes first (outside the DB transaction), each re-hashed by the content store.
    for p in sorted((stage / "artifacts").glob("*")) if (stage / "artifacts").is_dir() else []:
        ws.store.put_file(p)
    # Derived files: an existing local copy is reused only if byte-identical to the verified
    # pack copy; a differing one is quarantined (never deleted) and replaced.
    for p in sorted((stage / "results" / "derived").rglob("*")) if (stage / "results" / "derived").is_dir() else []:
        if p.is_file():
            dest = ws.path / p.relative_to(stage / "results")
            if dest.is_file() and hashlib.sha256(dest.read_bytes()).digest() == hashlib.sha256(p.read_bytes()).digest():
                continue
            if dest.exists():
                ws.store.quarantine(dest, "corrupted-derived")
                derived_repaired += 1
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + ".import.tmp")
            shutil.copyfile(p, tmp)
            os.replace(tmp, dest)
    with ws.db.transaction() as tx:
        tx.execute("PRAGMA defer_foreign_keys=ON")
        for folder, tables in (
            ("metadata", METADATA_TABLES),
            ("results", RESULT_TABLES),
            ("annotations", ANNOTATION_TABLES),
        ):
            for t in tables:
                rows = _load(stage, f"{folder}/{t}.jsonl")
                n = 0
                for r in rows:
                    if t == "product":
                        r["workspace_id"] = ws.id
                    if t == "artifact":
                        r["integrity_state"] = "AVAILABLE" if ws.store.exists(r["sha256"]) else "METADATA_ONLY"
                    cols = list(r)
                    cur = tx.execute(
                        f"INSERT OR IGNORE INTO {t}({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                        [r[c] for c in cols],
                    )
                    n += cur.rowcount
                stats[t] = n
        repo.audit(
            tx,
            "pack.import",
            None,
            None,
            {
                "rows": sum(stats.values()),
                "includes_artifacts": manifest["includes_artifacts"],
                # ACET-ARC-002: the archive hash is kept as provenance; its members became their own objects
                "archive_sha256": manifest.get("_archive_sha256"),
                "derived_repaired": derived_repaired,
            },
        )
    return {
        "rows_inserted": stats,
        "derived_repaired": derived_repaired,
        "includes_artifacts": manifest["includes_artifacts"],
        "archive_sha256": manifest.get("_archive_sha256"),
    }
