"""Collect the license texts that must ship with a distribution (ACET-LIC-001, docs/license-audit.json).

Usage:
  python tools/collect_licenses.py <out_dir>                    # installer: Python runtime + PySide6/shiboken6
  python tools/collect_licenses.py <out_dir> --venv <python>    # Engine Pack: every distribution of that venv

Fails (exit 1) when a required distribution or license file cannot be found: a missing
notice is a release blocker, never a silent omission.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

INSTALLER_DISTRIBUTIONS = ["PySide6", "PySide6_Essentials", "PySide6_Addons", "shiboken6"]
# Canonical texts vendored in packaging/licenses/ for distributions whose wheels ship none
# (PySide6/shiboken6 6.x and qbindiff 1.2.3 do not include a license file). The key is the
# SPDX expression chosen in docs/license-audit.json.
VENDORED = Path(__file__).resolve().parents[1] / "packaging" / "licenses"
FALLBACK_TEXTS = {
    "PySide6": ["LGPL-3.0-only.txt", "GPL-3.0-only.txt"],  # LGPL-3.0 incorporates GPL-3.0 by reference
    "PySide6_Essentials": ["LGPL-3.0-only.txt", "GPL-3.0-only.txt"],
    "PySide6_Addons": ["LGPL-3.0-only.txt", "GPL-3.0-only.txt"],
    "shiboken6": ["LGPL-3.0-only.txt", "GPL-3.0-only.txt"],
    "qbindiff": ["Apache-2.0.txt"],
}
LICENSE_HINTS = ("license", "licence", "copying", "notice", "authors")
SOURCES = {
    "PySide6": "https://download.qt.io/official_releases/QtForPython/",
    "PySide6_Essentials": "https://download.qt.io/official_releases/QtForPython/",
    "PySide6_Addons": "https://download.qt.io/official_releases/QtForPython/",
    "shiboken6": "https://download.qt.io/official_releases/QtForPython/",
    "python": "https://www.python.org/downloads/source/",
}


def _is_license_file(rel: str) -> bool:
    name = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return any(name.startswith(h) for h in LICENSE_HINTS) or "/licenses/" in rel.replace("\\", "/").lower()


def _dist_license_files(dist: metadata.Distribution) -> list[Path]:
    out = []
    for f in dist.files or []:
        if _is_license_file(str(f)):
            p = Path(str(dist.locate_file(f)))
            if p.is_file():
                out.append(p)
    return out


def _python_license() -> Path | None:
    for base in {Path(sys.base_prefix), Path(sys.prefix)}:
        for cand in ("LICENSE.txt", "LICENSE", f"lib/python{sys.version_info[0]}.{sys.version_info[1]}/LICENSE.txt"):
            if (base / cand).is_file():
                return base / cand
    return None


def collect_installer(out: Path) -> list[str]:
    missing: list[str] = []
    notices = []
    py = _python_license()
    if py is None:
        missing.append("python: LICENSE.txt not found in the runtime prefix")
    else:
        (out / "python").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(py, out / "python" / "LICENSE.txt")
        notices.append(("python", sys.version.split()[0], "PSF-2.0"))
    for name in INSTALLER_DISTRIBUTIONS:
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            missing.append(f"{name}: distribution not installed")
            continue
        files = _dist_license_files(dist) or [VENDORED / f for f in FALLBACK_TEXTS.get(name, [])]
        if not files or not all(f.is_file() for f in files):
            missing.append(f"{name}: no license file in the distribution and no vendored text")
            continue
        dest = out / name
        dest.mkdir(parents=True, exist_ok=True)
        for f in files:
            shutil.copyfile(f, dest / f.name)
        notices.append((name, dist.version, dist.metadata["License-Expression"] or dist.metadata["License"]))
    lines = ["Third-party components shipped with ACET", ""]
    for name, version, lic in notices:
        lines.append(f"{name} {version} — {lic}. Source: {SOURCES.get(name, 'see package metadata')}")
    lines += [
        "",
        "Qt for Python (PySide6, shiboken6) is used under LGPL-3.0-only. Its libraries are installed as separate,",
        "replaceable files; you may replace them with a modified version. Corresponding sources: see above.",
    ]
    (out / "THIRD-PARTY-NOTICES.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return missing


def collect_venv(out: Path, python: str) -> list[str]:
    """Ask the venv's interpreter for its distributions and their license files (isolated mode)."""
    probe = (
        "import json,importlib.metadata as m\n"
        "r=[]\n"
        "for d in m.distributions():\n"
        "  fs=[str(d.locate_file(f)) for f in (d.files or [])"
        " if any(str(f).replace('\\\\','/').rsplit('/',1)[-1].lower().startswith(h)"
        " for h in ('license','licence','copying','notice'))]\n"
        "  r.append({'name':d.metadata['Name'],'version':d.version,'files':fs})\n"
        "print(json.dumps(r))\n"
    )
    res = subprocess.run([python, "-I", "-c", probe], capture_output=True, text=True, check=True)
    missing = []
    for d in json.loads(res.stdout):
        files = [Path(f) for f in d["files"] if Path(f).is_file()]
        files = files or [VENDORED / f for f in FALLBACK_TEXTS.get(d["name"], []) if (VENDORED / f).is_file()]
        if not files:
            missing.append(f"{d['name']} {d['version']}: no license file in the distribution")
            continue
        dest = out / f"{d['name']}-{d['version']}"
        dest.mkdir(parents=True, exist_ok=True)
        for f in files:
            shutil.copyfile(f, dest / f.name)
    return missing


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--venv", metavar="PYTHON", help="collect from this interpreter's environment instead")
    args = ap.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    missing = collect_venv(args.out_dir, args.venv) if args.venv else collect_installer(args.out_dir)
    for m in missing:
        print(f"MISSING: {m}", file=sys.stderr)
    print(f"licenses collected in {args.out_dir}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
