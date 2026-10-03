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
from acet.platform import engine_manager
from acet.platform.doctor import system_checks, workspace_checks
from acet.platform.sanitize import sanitize, sanitize_obj

LOG_TAIL_BYTES = 64 * 1024
MAX_LOGS = 50


def _engine_pack_state() -> dict[str, Any]:
    """What the Engine Pack Manager sees: state, this build's distribution channel, trusted pack keys (ids only),
    the engines directory (names and sizes) and the active-pack pointer. No network access."""
    from acet.platform.signing import load_trust_store

    out: dict[str, Any] = {"platform": engine_manager.current_platform()}
    try:
        st = engine_manager.status()
        out["status"] = {k: st.get(k) for k in ("state", "pack", "profiles", "components", "verification")}
    except Exception as exc:  # the package must be produced even when the manager cannot read its state
        out["status_error"] = repr(exc)
    dist = engine_manager.distribution_config()
    out["distribution"] = {"channel": dist.get("channel"), "index_urls": dist.get("index_urls", [])}
    try:
        out["trusted_engine_pack_keys"] = sorted(
            f"{k}{' (dev)' if v.get('channel') == 'dev' else ''}{' REVOKED' if v.get('revoked') else ''}"
            for k, v in load_trust_store(local=True).items()
            if "engine-pack" in v.get("purposes", [])
        )
    except Exception as exc:
        out["trust_store_error"] = repr(exc)
    root = engine_manager.engines_root()
    pointer = engine_manager.pointer_path()
    out["pointer"] = json.loads(pointer.read_text(encoding="utf-8")) if pointer.is_file() else None
    out["engines_dir"] = {
        sub: [
            {"name": p.name, "size": p.stat().st_size if p.is_file() else None}
            for p in sorted((root / sub).iterdir() if (root / sub).is_dir() else [])
        ]
        for sub in ("downloads", "staging", "packs")
    }
    return out


def _engine_pack_logs() -> dict[str, str]:
    files: dict[str, str] = {}
    log = engine_manager.log_path()
    if log.is_file():
        files["logs/engine-pack-install.log"] = log.read_bytes()[-LOG_TAIL_BYTES:].decode("utf-8", "replace")
    reports = sorted(log.parent.glob("engine-pack-health-*.json"), key=lambda p: p.stat().st_mtime)[-3:]
    for p in reports:
        files[f"logs/{p.name}"] = p.read_bytes()[-4 * LOG_TAIL_BYTES :].decode("utf-8", "replace")
    return files


def create_diagnostic_package(ws: Workspace | None, dest: Path) -> Path:
    def s(obj: Any) -> str:
        plain = json.loads(json.dumps(obj, default=str))
        return json.dumps(sanitize_obj(plain, workspace=ws.path if ws else None), indent=2)

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
        "providers.json": s(
            {k: {**v.to_dict(), "location": None} for k, v in engine_manager.engine_environment().providers.items()}
        ),
        "engine_pack.json": s(_engine_pack_state()),
        "README.txt": "ACET diagnostic package. Contains no artifact bytes and no full user paths (ACC-032).\n",
    }
    for name, text in _engine_pack_logs().items():
        files[name] = sanitize(text, workspace=ws.path if ws else None)
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
