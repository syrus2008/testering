"""Release Evidence Bundle builder and gate checker (spec §89, §119, ACET-REL-001, ACC-050/099/139).

Usage:
  python tools/release_evidence.py build <out_dir> --artifacts dist/* [--sbom sbom.json] [--key secret.hex --key-id ID]
  python tools/release_evidence.py check <out_dir> [--channel STABLE]

``check`` refuses a STABLE release unless every required item exists and none is
marked NOT_RUN/FAILED. Items that cannot be produced automatically (clean-VM runs,
SmartScreen smoke) must be supplied as result files by the release owner — the tool
never fabricates them.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "release-manifest.json",
    "signatures/release-manifest.sig.json",
    "sbom/sbom.cdx.json",
    "licenses/license-audit.md",
    "compatibility-matrix.json",
    "migration-test-report.json",
    "acceptance-matrix.json",
    "benchmark-summary.json",
    "golden-results/",
    "clean-vm-install-results/windows10.json",
    "clean-vm-install-results/windows11.json",
    "security-scan-summary.json",
    "known-limitations.json",
    "checksums.txt",
]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def build(out: Path, artifacts: list[Path], sbom: Path | None, key: Path | None, key_id: str | None) -> None:
    sys.path.insert(0, str(ROOT / "src"))
    import acet
    from acet.platform.signing import sign_payload

    out.mkdir(parents=True, exist_ok=True)
    for sub in ("signatures", "sbom", "licenses", "golden-results", "clean-vm-install-results"):
        (out / sub).mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "docs" / "license-audit.md", out / "licenses" / "license-audit.md")
    shutil.copyfile(ROOT / "src" / "acet" / "platform" / "compatibility-matrix.json", out / "compatibility-matrix.json")
    shutil.copyfile(ROOT / "docs" / "traceability" / "acceptance-matrix.json", out / "acceptance-matrix.json")
    shutil.copyfile(ROOT / "src" / "acet" / "engines" / "known_limitations.json", out / "known-limitations.json")
    for b in sorted((ROOT / "benchmarks").glob("*.json")):
        shutil.copyfile(b, out / "golden-results" / b.name)
    bench = {b.stem: json.loads(b.read_text())["summary"] for b in sorted((ROOT / "benchmarks").glob("*.json"))}
    (out / "benchmark-summary.json").write_text(json.dumps(bench, indent=2), encoding="utf-8")
    if sbom is not None:
        shutil.copyfile(sbom, out / "sbom" / "sbom.cdx.json")
    for name in (
        "migration-test-report.json",
        "security-scan-summary.json",
        "clean-vm-install-results/windows10.json",
        "clean-vm-install-results/windows11.json",
    ):
        if not (out / name).exists():
            (out / name).write_text(
                json.dumps({"status": "NOT_RUN", "note": "must be supplied by the release pipeline"}), encoding="utf-8"
            )
    manifest = {
        "acet_version": acet.__version__,
        "commit": _git("rev-parse", "HEAD"),
        "tag": _git("describe", "--tags", "--always"),
        "build_id": f"local-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
        "artifacts": {a.name: _sha(a) for a in artifacts},
        "sbom_sha256": _sha(out / "sbom" / "sbom.cdx.json") if (out / "sbom" / "sbom.cdx.json").exists() else None,
        "created_at": datetime.now(UTC).isoformat(),
    }
    (out / "release-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if key is not None and key_id:
        env = sign_payload(manifest, bytes.fromhex(key.read_text().strip()), key_id)
        (out / "signatures" / "release-manifest.sig.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    lines = [
        f"{_sha(p)}  {p.relative_to(out).as_posix()}"
        for p in sorted(out.rglob("*"))
        if p.is_file() and p.name != "checksums.txt"
    ]
    (out / "checksums.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def check(out: Path, channel: str = "STABLE") -> list[str]:
    problems = []
    for item in REQUIRED:
        p = out / item
        if item.endswith("/"):
            if not p.is_dir() or not any(p.iterdir()):
                problems.append(f"missing or empty: {item}")
            continue
        if not p.is_file():
            problems.append(f"missing: {item}")
            continue
        if p.suffix == ".json":
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                problems.append(f"invalid JSON: {item}")
                continue
            if isinstance(data, dict) and data.get("status") in ("NOT_RUN", "FAILED"):
                problems.append(f"{item}: {data['status']}")
    if (out / "checksums.txt").is_file():
        for line in (out / "checksums.txt").read_text().splitlines():
            sha, _, rel = line.partition("  ")
            if not (out / rel).is_file() or _sha(out / rel) != sha:
                problems.append(f"checksum mismatch: {rel}")
    acc = out / "acceptance-matrix.json"
    if acc.is_file():
        summary = json.loads(acc.read_text()).get("summary") or {"not_started": "unknown"}
        if summary.get("not_started") or summary.get("partial"):
            problems.append(f"acceptance criteria incomplete: {summary}")
    return problems if channel == "STABLE" else [p for p in problems if "checksum" in p]


if __name__ == "__main__":
    cmd, out = sys.argv[1], Path(sys.argv[2])
    if cmd == "build":
        arts = (
            [Path(a) for a in sys.argv[sys.argv.index("--artifacts") + 1 :] if not a.startswith("--")]
            if "--artifacts" in sys.argv
            else []
        )
        arts = [a for a in arts if a.is_file()]
        sb = Path(sys.argv[sys.argv.index("--sbom") + 1]) if "--sbom" in sys.argv else None
        k = Path(sys.argv[sys.argv.index("--key") + 1]) if "--key" in sys.argv else None
        kid = sys.argv[sys.argv.index("--key-id") + 1] if "--key-id" in sys.argv else None
        build(out, arts, sb, k, kid)
        print(f"evidence bundle written to {out}")
    else:
        ch = sys.argv[sys.argv.index("--channel") + 1] if "--channel" in sys.argv else "STABLE"
        probs = check(out, ch)
        print("\n".join(probs) or "release evidence complete")
        raise SystemExit(1 if probs else 0)
