"""Ghidra headless provider (spec §16, §71: ACET-GHD-004/005/006).

Runs ``analyzeHeadless`` from inside the supervised worker with a project
directory private to this processor run (deleted afterwards), the profile's
analyzer selection (pre-script) and a native per-file timeout. The external
Supervisor watchdog remains the second, independent timeout. The Ghidra project
is derived and disposable — never a source of truth.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from acet.engines.proc import run_engine
from acet.engines.worker import WorkerContext

SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"
EXPORT_FORMAT = "acet-ghidra-export@1"


def headless_path(ghidra_dir: Path) -> Path:
    return ghidra_dir / "support" / ("analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless")


def ghidra_version(ghidra_dir: Path) -> str | None:
    try:
        m = re.search(
            r"^application\.version=(.+)$",
            (ghidra_dir / "Ghidra" / "application.properties").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        return m.group(1).strip() if m else None
    except OSError:
        return None


def run_headless(
    ctx: WorkerContext, binary: Path, *, post_scripts: list[tuple[str, list[str]]], work: Path
) -> tuple[int, int]:
    gdir = Path(os.environ["ACET_GHIDRA_DIR"])
    ctx.engine_version = f"ghidra-{ghidra_version(gdir)}"
    project = work / "ghidra_project"
    project.mkdir(parents=True, exist_ok=True)
    analyzers = work / "analyzers.json"
    analyzers.write_text(json.dumps(ctx.config.get("analyzers", {})), encoding="utf-8")
    native_timeout = int(ctx.config.get("native_timeout_s", max(60, int(ctx.config.get("soft_timeout_s", 1500)) - 60)))
    argv = [
        str(headless_path(gdir)),
        str(project),
        "acet",
        "-import",
        str(binary),
        "-readOnly",
        "-scriptPath",
        str(SCRIPTS),
        "-preScript",
        "AcetSetAnalyzers.java",
        str(analyzers),
        "-analysisTimeoutPerFile",
        str(native_timeout),
        "-max-cpu",
        str(int(ctx.config.get("max_cpu", 2))),
    ]
    for name, args in post_scripts:
        argv += ["-postScript", name, *args]
    errors = 0

    def on_line(line: str) -> None:
        nonlocal errors
        if re.search(r"^\s*ERROR\b", line):
            errors += 1

    ctx.auto_heartbeat = False
    code = run_engine(argv, cwd=work, heartbeat=ctx.heartbeat, stop_requested=ctx.stop_requested, on_line=on_line)
    shutil.rmtree(project, ignore_errors=True)  # ACET-GHD-006: never shared, never kept
    return code, errors


def replay(ctx: WorkerContext, replay_dir: Path) -> dict[str, Any]:
    """Golden replay provider: serve a recorded real Ghidra export for a known artifact hash.

    Used by CI machines without Ghidra (golden tests). Never presented as a live engine:
    the engine version carries ``replay:`` and the provider is reported unverified.
    """
    rec = replay_dir / f"{ctx.inputs[0].sha256}.json"
    if not rec.is_file():
        ctx.skip("SKIPPED_INCOMPATIBLE", "no recorded Ghidra export for this artifact (replay provider)")
    data: dict[str, Any] = json.loads(rec.read_text(encoding="utf-8"))
    ctx.engine_version = f"replay:{data.get('engine_version')}"
    data["engine_version"] = ctx.engine_version
    ctx.count("functions", len(data.get("functions", [])))
    return data


def extract(ctx: WorkerContext) -> dict[str, Any]:
    if os.environ.get("ACET_GHIDRA_REPLAY_DIR") and not os.environ.get("ACET_GHIDRA_DIR"):
        return replay(ctx, Path(os.environ["ACET_GHIDRA_REPLAY_DIR"]))
    binary = ctx.artifact_path(0)
    work = ctx.output_dir / "_work"
    work.mkdir(exist_ok=True)
    export = work / "export.json"
    code, log_errors = run_headless(ctx, binary, post_scripts=[("AcetExport.java", [str(export)])], work=work)
    if code != 0:
        ctx.error(f"analyzeHeadless exit code {code}")
    if not export.is_file():
        ctx.error("Ghidra export missing (analysis incomplete)")
        shutil.rmtree(work, ignore_errors=True)
        return {"format": EXPORT_FORMAT, "status": "invalid", "functions": [], "program": None}
    data: dict[str, Any] = json.loads(export.read_text(encoding="utf-8"))
    shutil.rmtree(work, ignore_errors=True)
    # ACET validates the provider's output instead of trusting it (INV-014).
    if data.get("format") != EXPORT_FORMAT or data.get("status") != "complete":
        ctx.error("unexpected Ghidra export format/status")
    if data.get("program", {}).get("executable_sha256") != ctx.inputs[0].sha256:
        ctx.error("Ghidra analysed bytes differ from the requested artifact")
    if data.get("counts", {}).get("functions") != len(data.get("functions", [])):
        ctx.error("function count mismatch in export")
    if log_errors:
        ctx.warn(f"Ghidra log contains {log_errors} ERROR line(s)")
    if data.get("program", {}).get("error_bookmarks"):
        ctx.warn(f"Ghidra recorded {data['program']['error_bookmarks']} error bookmark(s)")
    ctx.count("functions", len(data.get("functions", [])))
    ctx.count("instructions", int(data.get("counts", {}).get("instructions", 0)))
    data["engine_version"] = ctx.engine_version
    data["analyzers"] = ctx.config.get("analyzers", {})
    return data
