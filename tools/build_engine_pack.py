"""Assemble, sign and publish an Engine Pack (spec §46, §64; ADR-0013).

Usage:
  python tools/build_engine_pack.py <config.json> <out_dir> --key-file <secret.hex> --key-id <id>
      [--archive <file.acetengine>] [--index <index.json> --url <published archive URL>]

config.json: {"id", "version", "supported_acet", "providers": [...provider manifest...],
              "licenses": [...], "sources": {"<dest subdir>": "<source path>"},
              "runtime": {"java": {"path": "runtime/java", "version": "21.0.x"}},   (private Java, optional)
              "components": [{"id", "name", "version", "license", "source_url"}]}  (shown before consent)

Every copied file is hashed into the manifest; the manifest is signed (ACET-SUP-001). ``--archive`` writes the
distributable ``.acetengine`` (deterministic zip, executables keep their mode); ``--index`` writes the signed
index the Engine Pack Manager resolves (the index is signed with the same release key; only keys of the
bundled trust store are accepted for it).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "engine-pack.json"


def build(config: dict[str, Any], out: Path, secret: bytes, key_id: str) -> Path:
    sys.path.insert(0, str(ROOT / "src"))
    from acet.domain.jsonschema import validate_named
    from acet.platform.signing import sign_payload

    # Fail on a bad config before copying hundreds of MB.
    validate_named({**_manifest(config), "checksums": {}, "installed_size": 0}, "engine-pack")
    out.mkdir(parents=True, exist_ok=True)
    for dest, src in config.get("sources", {}).items():
        target = out / dest
        if Path(src).is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True, symlinks=False)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
    files = [p for p in sorted(out.rglob("*")) if p.is_file() and p.name != MANIFEST]
    checksums = {p.relative_to(out).as_posix(): _sha(p) for p in files}
    manifest = {
        **_manifest(config),
        "checksums": checksums,
        "installed_size": sum(p.stat().st_size for p in files),
    }
    validate_named(manifest, "engine-pack")
    (out / MANIFEST).write_text(json.dumps(sign_payload(manifest, secret, key_id), indent=2), encoding="utf-8")
    return out


def _manifest(config: dict[str, Any]) -> dict[str, Any]:
    m: dict[str, Any] = {
        "id": config["id"],
        "version": config["version"],
        "protocol_version": 1,
        "providers": config["providers"],
        "licenses": config["licenses"],
        "supported_acet": config["supported_acet"],
    }
    for k in ("runtime", "components"):
        if k in config:
            m[k] = config[k]
    return m


def make_archive(pack_dir: Path, archive: Path) -> Path:
    """Deterministic zip of a built pack: sorted members, fixed timestamps, executable bits preserved."""
    archive.parent.mkdir(parents=True, exist_ok=True)
    tmp = archive.with_name(archive.name + ".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for p in sorted(pack_dir.rglob("*")):
            if not p.is_file():
                continue
            info = zipfile.ZipInfo(p.relative_to(pack_dir).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            mode = 0o755 if os.access(p, os.X_OK) or p.suffix in (".exe", ".bat", ".cmd") else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(p, "rb") as src, z.open(info, "w", force_zip64=True) as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
    os.replace(tmp, archive)
    return archive


def index_entry(pack_dir: Path, archive: Path, url: str) -> dict[str, Any]:
    m = json.loads((pack_dir / MANIFEST).read_text(encoding="utf-8"))["payload"]
    return {
        "id": m["id"],
        "version": m["version"],
        "supported_acet": m["supported_acet"],
        "archive_url": url,
        "archive_sha256": _sha(archive),
        "archive_size": archive.stat().st_size,
        "installed_size": m.get("installed_size"),
        "components": m.get("components", []),
        "licenses": m["licenses"],
    }


def make_index(entries: list[dict[str, Any]], secret: bytes, key_id: str) -> dict[str, Any]:
    sys.path.insert(0, str(ROOT / "src"))
    from acet.platform.signing import sign_payload

    return sign_payload({"kind": "acet-engine-pack-index", "schema_version": 1, "packs": entries}, secret, key_id)


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build, sign and publish an ACET Engine Pack.")
    ap.add_argument("config", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--key-file", type=Path, required=True, help="hex Ed25519 seed (keep outside the repository)")
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--archive", type=Path, help="also write the distributable .acetengine archive")
    ap.add_argument("--index", type=Path, help="also write a signed index for --url (needs --archive)")
    ap.add_argument("--url", help="URL where the archive will be published (HTTPS)")
    args = ap.parse_args(argv)
    if args.index and not (args.archive and args.url):
        ap.error("--index needs --archive and --url")
    secret = bytes.fromhex(args.key_file.read_text(encoding="ascii").strip())
    pack = build(json.loads(args.config.read_text(encoding="utf-8")), args.out_dir, secret, args.key_id)
    print(f"engine pack written to {pack}")
    if args.archive:
        make_archive(pack, args.archive)
        print(f"archive written to {args.archive}")
    if args.index:
        args.index.write_text(json.dumps(make_index([index_entry(pack, args.archive, args.url)], secret, args.key_id),
                                         indent=2), encoding="utf-8")  # fmt: skip
        print(f"signed index written to {args.index}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
