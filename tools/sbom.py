"""Generate a CycloneDX 1.5 SBOM from the real build environment (ACET-SUP-003, ACC-059).

Usage: python tools/sbom.py out.json [--engine-pack <pack dir>]
Lists ACET, its runtime dependencies (stdlib-only core + optional UI), the Python runtime
and, when given, the components declared by an Engine Pack.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import uuid
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PACKAGES = ["PySide6", "shiboken6"]  # optional UI extra; core is stdlib-only


def _component(name: str, version: str, ctype: str = "library", **extra: object) -> dict[str, object]:
    return {"type": ctype, "name": name, "version": version, "bom-ref": f"{name}@{version}", **extra}


def build_sbom(engine_pack: Path | None = None) -> dict[str, object]:
    sys.path.insert(0, str(ROOT / "src"))
    import acet

    comps = [_component("python", platform.python_version(), "platform")]
    for name in RUNTIME_PACKAGES:
        try:
            dist = metadata.distribution(name)
            comps.append(
                _component(
                    name, dist.version, licenses=[{"license": {"name": dist.metadata.get("License") or "see package"}}]
                )
            )
        except metadata.PackageNotFoundError:
            continue
    if engine_pack is not None:
        env = json.loads((engine_pack / "engine-pack.json").read_text(encoding="utf-8"))
        for p in env["payload"]["providers"]:
            comps.append(
                _component(
                    p["provider_id"],
                    p["provider_version"],
                    "application",
                    properties=[{"name": "acet:license_mode", "value": p["license_mode"]}],
                )
            )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": _component("acet", acet.__version__, "application"),
            "tools": [{"name": "acet tools/sbom.py"}],
        },
        "components": comps,
    }


if __name__ == "__main__":
    out = Path(sys.argv[1])
    pack = Path(sys.argv[sys.argv.index("--engine-pack") + 1]) if "--engine-pack" in sys.argv else None
    sbom = build_sbom(pack)
    out.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(hashlib.sha256(out.read_bytes()).hexdigest())
