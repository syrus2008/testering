"""Engine Packs: verify, install side by side, pin, denylist (spec §46, §64, §115, ACET-UPD-001/002/005,
ACET-SUP-001/005, ACET-LIC-001, ACC-034/057/058/061/062/086/090/091/127).

Layout of a pack directory/zip:  engine-pack.json (signed envelope)  files...
An Engine Pack is never activated silently: workspaces stay pinned until a user
explicitly changes the pin. Revoked packs are refused for new runs; history
that references them is preserved.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from importlib import resources
from pathlib import Path
from typing import Any

import acet
from acet.domain.error_codes import AcetError
from acet.domain.jsonschema import SchemaValidationError, validate_named
from acet.platform.paths import acet_home
from acet.platform.signing import load_trust_store, verify_envelope

PROTOCOL_VERSION = 1


def packs_root() -> Path:
    return acet_home() / "engines" / "packs"


def denylist_path() -> Path:
    return acet_home() / "config" / "denylist.json"


def load_denylist() -> list[dict[str, Any]]:
    p = denylist_path()
    return json.loads(p.read_text(encoding="utf-8")).get("revoked", []) if p.is_file() else []


def is_revoked(pack_id: str, version: str) -> dict[str, Any] | None:
    return next(
        (
            r
            for r in load_denylist()
            if r.get("kind") == "engine_pack" and r.get("id") == pack_id and r.get("version") in (version, "*")
        ),
        None,
    )


def _vt(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def version_in_range(version: str, spec: str) -> bool:
    ok = True
    for part in spec.split(","):
        m = re.match(r"\s*(>=|<=|<|>|==)\s*([\w.]+)", part)
        if m:
            op, ref = m.groups()
            a, b = _vt(version), _vt(ref)
            ok &= {">=": a >= b, "<=": a <= b, "<": a < b, ">": a > b, "==": a == b}[op]
    return ok


def verify_pack(root: Path, *, trust_extra: Path | None = None) -> dict[str, Any]:
    """Signature → schema → protocol/compat → licenses → every file hash. Nothing runs before this passes."""
    env = json.loads((root / "engine-pack.json").read_text(encoding="utf-8"))
    manifest = verify_envelope(env, load_trust_store(trust_extra), purpose="engine-pack")
    try:
        validate_named(manifest, "engine-pack")
    except SchemaValidationError as exc:
        raise AcetError("ACET-UPD-001", f"invalid engine pack manifest: {exc}") from exc
    if manifest["protocol_version"] != PROTOCOL_VERSION:
        raise AcetError("ACET-UPD-001", f"provider protocol v{manifest['protocol_version']} unsupported (ACC-086)")
    if not version_in_range(acet.__version__, manifest["supported_acet"]):
        raise AcetError("ACET-UPD-001", f"pack supports ACET {manifest['supported_acet']}, this is {acet.__version__}")
    licensed = {lic["component"] for lic in manifest["licenses"]}
    unlicensed = [
        p["provider_id"]
        for p in manifest["providers"]
        if p["license_mode"] == "bundled" and p["provider_id"] not in licensed
    ]
    if unlicensed:
        raise AcetError("ACET-UPD-001", f"bundled providers without license decision: {unlicensed} (ACET-LIC-001)")
    for rel, sha in sorted(manifest["checksums"].items()):
        p = root / rel
        if ".." in Path(rel).parts or Path(rel).is_absolute() or not p.is_file():
            raise AcetError("ACET-PACK-001", f"pack file missing or unsafe: {rel}")
        if hashlib.sha256(p.read_bytes()).hexdigest() != sha:
            raise AcetError("ACET-PACK-001", f"pack file tampered: {rel} (ACC-058)")
    if is_revoked(manifest["id"], manifest["version"]):
        raise AcetError("ACET-UPD-001", f"engine pack {manifest['id']}@{manifest['version']} is revoked (ACC-090)")
    return manifest


def install_pack(src: Path, *, trust_extra: Path | None = None) -> Path:
    manifest = verify_pack(src, trust_extra=trust_extra)
    dest = packs_root() / f"{manifest['id']}-{manifest['version']}"
    if dest.exists():
        return dest  # immutable once installed; coexistence by version (ACET-UPD-005)
    tmp = dest.with_name(dest.name + ".staging")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    verify_pack(tmp, trust_extra=trust_extra)  # re-verify the staged copy before activation
    tmp.rename(dest)
    return dest


def installed_packs() -> list[dict[str, Any]]:
    out = []
    root = packs_root()
    for d in sorted(root.iterdir()) if root.is_dir() else []:
        try:
            env = json.loads((d / "engine-pack.json").read_text(encoding="utf-8"))
            m = env["payload"]
            out.append(
                {
                    "id": m["id"],
                    "version": m["version"],
                    "path": str(d),
                    "revoked": bool(is_revoked(m["id"], m["version"])),
                    "manifest_hash": hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest(),
                }
            )
        except (OSError, KeyError, ValueError):
            continue
    return out


def resolve_pinned(pin: str | None) -> dict[str, Any] | None:
    """Return the installed pack matching ``id@version`` (old packs stay usable, ACC-034/062)."""
    if not pin:
        return None
    pid, _, ver = pin.partition("@")
    for p in installed_packs():
        if p["id"] == pid and p["version"] == ver:
            if p["revoked"]:
                raise AcetError("ACET-UPD-001", f"pinned engine pack {pin} is revoked; new runs refused (ACC-090)")
            return p
    raise AcetError("ACET-UPD-001", f"pinned engine pack {pin} is not installed")


def provider_overrides(pack: dict[str, Any]) -> dict[str, str]:
    """Map provider ids to executables inside an installed pack (feeds engines.environment.detect)."""
    root = Path(pack["path"])
    m = json.loads((root / "engine-pack.json").read_text(encoding="utf-8"))["payload"]
    out: dict[str, str] = {}
    for p in m["providers"]:
        out[p["provider_id"]] = str(root / p["executable"])
    return out


def compatibility_matrix() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (resources.files("acet.platform") / "compatibility-matrix.json").read_text(encoding="utf-8")
    )
    return data


def provider_status(provider_id: str, version: str | None) -> str:
    """'validated' | 'experimental' | 'unverified' (ACC-092)."""
    for p in compatibility_matrix()["providers"]:
        if p["provider_id"] == provider_id:
            if version and any(str(version).startswith(v.split(" ")[0]) for v in p["versions"]):
                return str(p["status"]) if p["status"] in ("validated", "experimental") else "unverified"
            return "unverified"
    return "unverified"
