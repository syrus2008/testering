"""Smoke test of a frozen (PyInstaller) ACET build — the artifact users run, not the sources.

Usage: python tools/frozen_smoke.py <dist/ACET> [--expect-verified]

Runs the frozen ``acet`` with a minimal environment (no Python on PATH, isolated ACET_HOME):
``--version``, a FAST analysis of the demo build (workers start as ``acet __worker__``) and
``doctor --full``, whose golden self-test must use the packaged demo dataset. With
``--expect-verified`` (an Engine Pack configured through ACET_GHIDRA_DIR / ACET_GHIDRIFF_PYTHON),
the self-test must be VERIFIED against live engines. Exit 1 on the first failure.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASSTHROUGH = (
    "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME", "JAVA_HOME",
    "ACET_GHIDRA_DIR", "ACET_GHIDRIFF_PYTHON", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON",
)  # fmt: skip


def _env(home: Path, **extra: str) -> dict[str, str]:
    env = {k: os.environ[k] for k in PASSTHROUGH if k in os.environ}
    # PATH without any Python: the frozen build must be self-contained (ACC-001).
    java = [str(Path(os.environ["JAVA_HOME"]) / "bin")] if "JAVA_HOME" in os.environ else []
    system = (
        ["/usr/bin", "/bin"]
        if os.name != "nt"
        else [str(Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32")]
    )
    env["PATH"] = os.pathsep.join(java + system)
    env["ACET_HOME"] = str(home)
    env.update(extra)
    return env


def _run(exe: Path, args: list[str], env: dict[str, str], ok: tuple[int, ...] = (0,)) -> str:
    res = subprocess.run([str(exe), *args], capture_output=True, text=True, env=env, timeout=3600)
    if res.returncode not in ok:
        raise SystemExit(
            f"FAIL: acet {' '.join(args)} exited {res.returncode}\n{res.stdout[-2000:]}\n{res.stderr[-2000:]}"
        )
    return res.stdout


def check(c: bool, msg: str) -> None:
    if not c:
        raise SystemExit(f"FAIL: {msg}")
    print(f"ok - {msg}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Smoke test a frozen ACET build.")
    ap.add_argument("dist", type=Path, help="PyInstaller output folder (dist/ACET)")
    ap.add_argument("--expect-verified", action="store_true", help="require a VERIFIED self-test (live engines)")
    args = ap.parse_args(argv)
    exe = args.dist / ("acet.exe" if os.name == "nt" else "acet")
    check(exe.is_file(), f"frozen executable present: {exe}")
    home = Path(tempfile.mkdtemp(prefix="acet-frozen-smoke-"))
    env = _env(home)
    check(_run(exe, ["--version"], env).startswith("acet "), "acet --version")
    ws = json.loads(_run(exe, ["workspace", "create", "smoke", "--json"], env))
    wenv = {**env, "ACET_WORKSPACE": ws["path"]}
    _run(exe, ["product", "create", "Fictional Guard", "--json"], wenv)
    demo = ROOT / "datasets" / "demo" / "builds" / "v1"
    build = json.loads(_run(exe, ["import", str(demo), "--product", "Fictional Guard", "--json"], wenv))
    run = json.loads(_run(exe, ["analyze", build["build_id"], "--profile", "FAST@1", "--json"], wenv))
    check(
        run["status"] == "COMPLETED" and run["coverage"] == 1.0,
        f"FAST analysis through frozen workers ({run['status']})",
    )
    _run(exe, ["engines", "recover", "--json"], env)
    eng = json.loads(_run(exe, ["engines", "status", "--json"], env, ok=(0, 10)))
    check(eng["profiles"]["FAST"]["state"] == "READY", "Engine Manager: FAST READY in the frozen build")
    doc = json.loads(_run(exe, ["doctor", "--full", "--json"], env, ok=(0, 10)))
    st = next(c for c in doc["checks"] if c["name"] == "golden self-test")["data"]["self_test"]
    checks = {c["name"]: c["ok"] for c in st["checks"]}
    check(checks.get("import") is True and checks.get("FAST facts") is True, "self-test uses the packaged demo dataset")
    check(st["verdict"] != "FAILED", f"golden self-test not FAILED ({st['verdict']}, engines {st['engine_mode']})")
    if args.expect_verified:
        check(st["verdict"] == "VERIFIED" and st["engine_mode"] == "live", "golden self-test VERIFIED on live engines")
    print("frozen smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
