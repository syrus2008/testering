"""Assemble and sign an Engine Pack directory (spec §46).

Usage: python tools/build_engine_pack.py <config.json> <out_dir> --key <secret.hex> --key-id <id>

config.json: {"id", "version", "supported_acet", "providers": [...provider manifest...],
              "licenses": [...], "sources": {"<dest subdir>": "<source path>"}}
Every copied file is hashed into the manifest; the manifest is signed (ACET-SUP-001).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(config: dict, out: Path, secret: bytes, key_id: str) -> Path:
    sys.path.insert(0, str(ROOT / "src"))
    from acet.domain.jsonschema import validate_named
    from acet.platform.signing import sign_payload

    out.mkdir(parents=True, exist_ok=True)
    for dest, src in config.get("sources", {}).items():
        target = out / dest
        if Path(src).is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True, symlinks=False)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
    checksums = {
        p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(out.rglob("*"))
        if p.is_file() and p.name != "engine-pack.json"
    }
    manifest = {
        "id": config["id"],
        "version": config["version"],
        "protocol_version": 1,
        "providers": config["providers"],
        "licenses": config["licenses"],
        "checksums": checksums,
        "supported_acet": config["supported_acet"],
    }
    validate_named(manifest, "engine-pack")
    (out / "engine-pack.json").write_text(
        json.dumps(sign_payload(manifest, secret, key_id), indent=2), encoding="utf-8"
    )
    return out


if __name__ == "__main__":
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    key = bytes.fromhex(Path(sys.argv[sys.argv.index("--key") + 1]).read_text().strip())
    build(cfg, Path(sys.argv[2]), key, sys.argv[sys.argv.index("--key-id") + 1])
    print("engine pack written")
