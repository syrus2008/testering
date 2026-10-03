"""Diagnostic package (spec §44, ACC-032/076): versions, provider states, job states,
integrity_check, sanitized config and filtered logs. Never artifact bytes, never full user paths."""

from __future__ import annotations

import json
import platform as _platform
import sqlite3
import sys
import zipfile
from pathlib import Path
from typing import Any

import acet
from acet.application.workspace import Workspace
from acet.domain.timeutil import utc_now_iso
from acet.engines.environment import detect
from acet.platform.doctor import system_checks, workspace_checks
from acet.platform.sanitize import sanitize

LOG_TAIL_BYTES = 64 * 1024
MAX_LOGS = 50


def create_diagnostic_package(ws: Workspace | None, dest: Path) -> Path:
    def s(obj: Any) -> str:
        return sanitize(json.dumps(obj, indent=2, default=str), workspace=ws.path if ws else None)

    files: dict[str, str] = {
        "versions.json": s(
            {
                "acet": acet.__version__,
                "python": sys.version.split()[0],
                "sqlite": sqlite3.sqlite_version,
                "os": f"{_platform.system()} {_platform.release()}",
                "generated_at": utc_now_iso(),
            }
        ),
        "system_checks.json": s([c.to_dict() for c in system_checks()]),
        "providers.json": s({k: {**v.to_dict(), "location": None} for k, v in detect().providers.items()}),
        "README.txt": "ACET diagnostic package. Contains no artifact bytes and no full user paths (ACC-032).\n",
    }
    if ws is not None:
        checks, _rec = workspace_checks(ws, full=False)
        files["workspace_checks.json"] = s([c.to_dict() for c in checks])
        files["jobs.json"] = s(
            [
                dict(r)
                for r in ws.db.conn.execute(
                    "SELECT id, job_type, state, stage, error_code, attempts, updated_at FROM job ORDER BY seq DESC LIMIT 200"
                )
            ]
        )
        files["runs.json"] = s(
            [
                dict(r)
                for r in ws.db.conn.execute(
                    "SELECT id, scope_type, status, coverage, acet_version FROM analysis_run ORDER BY seq DESC LIMIT 200"
                )
            ]
        )
        files["settings.json"] = s(
            {
                r["key"]: "<set>" if "secret" in r["key"] else json.loads(r["value_json"])
                for r in ws.db.conn.execute("SELECT key, value_json FROM settings")
            }
        )
        logs = sorted(
            (ws.path / "logs" / "processor_runs").glob("*/*.log"), key=lambda p: p.stat().st_mtime, reverse=True
        )[:MAX_LOGS]
        for p in logs:
            data = p.read_bytes()[-LOG_TAIL_BYTES:].decode("utf-8", "replace")
            files[f"logs/{p.parent.name}/{p.name}"] = sanitize(data, workspace=ws.path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, text in sorted(files.items()):
            z.writestr(name, text)
    tmp.replace(dest)
    return dest
