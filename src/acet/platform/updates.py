"""Verified updates with rollback (spec §65, ACET-UPD-003/004/006, ACET-SUP-001/005, ACC-060/089/090/149).

An offline bundle is a zip: ``update.json`` (signed envelope) + payload files.
States follow the canonical UPDATE machine:
AVAILABLE → DOWNLOADING → DOWNLOADED → VERIFYING → VERIFIED → STAGING → STAGED →
APPLYING → VALIDATING → COMMITTED, with FAILED before commit and ROLLBACK after apply.
Nothing from the bundle is executed or activated before signature + hashes + compatibility
pass. Installation layout (portable/installer-agnostic):

    <install_root>/versions/<version>/...      immutable app trees
    <install_root>/current.json                {"version": ..., "previous": ...}  (atomic pointer)

Workspaces are never touched by an app update; DB migrations run on next open with backup
(ACET-UPD-003, ACC-130).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acet.domain.error_codes import AcetError
from acet.domain.jsonschema import SchemaValidationError, validate_named
from acet.domain.state_machines import UPDATE
from acet.platform.engine_packs import denylist_path, version_in_range
from acet.platform.signing import load_trust_store, verify_envelope
from acet.reporting.acetpack import ArchiveLimits, check_archive

CHANNELS = ("STABLE", "BETA", "DEVELOPER")


@dataclass
class UpdateRecord:
    state: str = UPDATE.initial
    history: list[str] = field(default_factory=lambda: [UPDATE.initial])
    error: str | None = None

    def go(self, dst: str) -> None:
        self.state = UPDATE.check(self.state, dst)
        self.history.append(dst)


def _pointer(root: Path) -> dict[str, Any]:
    p = root / "current.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"version": None, "previous": None}


def _write_pointer(root: Path, data: dict[str, Any]) -> None:
    tmp = root / "current.json.tmp"
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, root / "current.json")


def current_version(root: Path) -> str | None:
    v = _pointer(root).get("version")
    return str(v) if v else None


def apply_offline_bundle(
    bundle: Path,
    install_root: Path,
    *,
    current: str,
    channel: str = "STABLE",
    validate: Callable[[Path], bool] | None = None,
    trust_extra: Path | None = None,
) -> UpdateRecord:
    """Verify then apply an offline update. ``validate`` is the post-update self-test (golden)."""
    rec = UpdateRecord()
    install_root.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="acet-update-", dir=install_root))
    try:
        rec.go("DOWNLOADING")
        local = stage / "bundle.zip"
        shutil.copyfile(bundle, local)  # offline: "download" is a copy of a local file (ACET-UPD-006)
        rec.go("DOWNLOADED")
        rec.go("VERIFYING")
        with zipfile.ZipFile(local) as z:
            check_archive_update(z)
            env = json.loads(z.read("update.json"))
            manifest = verify_envelope(env, load_trust_store(trust_extra), purpose="update")
            try:
                validate_named(manifest, "update-manifest")
            except SchemaValidationError as exc:
                raise AcetError("ACET-UPD-001", f"invalid update manifest: {exc}") from exc
            if manifest.get("channel") not in CHANNELS or manifest["channel"] != channel:
                raise AcetError("ACET-UPD-001", f"channel mismatch ({manifest.get('channel')} vs {channel})")
            if not version_in_range(current, manifest["compatible_from"]):
                raise AcetError("ACET-UPD-001", f"update requires current version {manifest['compatible_from']}")
            files = manifest["files"]
            members = set(z.namelist()) - {"update.json"}
            if members != set(files):
                raise AcetError("ACET-PACK-001", "bundle members do not match the signed manifest")
            payload = stage / "payload"
            for name, sha in sorted(files.items()):
                data = z.read(name)
                if hashlib.sha256(data).hexdigest() != sha:
                    raise AcetError("ACET-PACK-001", f"update file tampered: {name}")
                out = payload / name
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
        rec.go("VERIFIED")
        rec.go("STAGING")
        version = str(manifest["version"])
        target = install_root / "versions" / version
        if target.exists():
            raise AcetError("ACET-UPD-001", f"version {version} already installed")
        shutil.copytree(payload, target.with_name(version + ".staging"))
        rec.go("STAGED")
        rec.go("APPLYING")
        os.replace(target.with_name(version + ".staging"), target)
        previous = _pointer(install_root).get("version")
        _write_pointer(install_root, {"version": version, "previous": previous})
        for item in manifest.get("revoked", []):  # ACET-SUP-005: denylist travels with signed updates
            _add_revocation(item)
        rec.go("VALIDATING")
        ok = validate(target) if validate is not None else True
        if not ok:
            rec.go("ROLLBACK")
            _write_pointer(install_root, {"version": previous, "previous": None})
            shutil.rmtree(target, ignore_errors=True)
            rec.go("ROLLED_BACK")
            rec.error = "post-update validation failed; previous version restored"
            return rec
        rec.go("COMMITTED")
        return rec
    except AcetError as exc:
        rec.error = f"{exc.code}: {exc.detail}"
        if rec.state in ("APPLYING", "VALIDATING"):
            rec.go("ROLLBACK")
            rec.go("RECOVERY_REQUIRED")
        elif UPDATE.can(rec.state, "FAILED"):
            rec.go("FAILED")
        return rec
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def check_archive_update(z: zipfile.ZipFile) -> None:
    names = set(z.namelist())
    if "update.json" not in names:
        raise AcetError("ACET-PACK-001", "update.json missing")
    check_archive(z, ArchiveLimits(), require=("update.json",))  # same limits as packs (ACET-ARC-001)


def _add_revocation(item: dict[str, Any]) -> None:
    p = denylist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"revoked": []}
    if item not in data["revoked"]:
        data["revoked"].append(item)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def rollback(install_root: Path) -> str | None:
    """Manual rollback to the previous version (ACET-UPD-004)."""
    ptr = _pointer(install_root)
    if not ptr.get("previous"):
        raise AcetError("ACET-UPD-002", "no previous version recorded")
    _write_pointer(install_root, {"version": ptr["previous"], "previous": ptr["version"]})
    return str(ptr["previous"])
