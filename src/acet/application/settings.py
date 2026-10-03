"""Workspace settings, usage modes and configuration precedence (spec §85, §110, ACET-MODE-001, ACC-098).

Precedence (lowest → highest): built-in defaults, Engine Pack defaults, workspace
settings, product profile hints, analysis profile, explicit run overrides (Research/
Developer only). Scientific parameters cannot be changed in Normal mode.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.canonical import stable_json
from acet.domain.error_codes import AcetError
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo


class Mode(StrEnum):
    NORMAL = "NORMAL"
    ADVANCED = "ADVANCED"
    RESEARCH = "RESEARCH"
    DEVELOPER = "DEVELOPER"


RANK = {Mode.NORMAL: 0, Mode.ADVANCED: 1, Mode.RESEARCH: 2, Mode.DEVELOPER: 3}

# key -> (default, minimum mode required to change it)
SETTINGS: dict[str, tuple[Any, Mode]] = {
    "ui.mode": ("NORMAL", Mode.NORMAL),
    "analysis.default_profile": ("STANDARD@1", Mode.NORMAL),
    "power.prevent_sleep_during_heavy_jobs": (False, Mode.NORMAL),
    "power.pause_heavy_on_battery": (True, Mode.NORMAL),
    "network.enabled": (False, Mode.ADVANCED),
    "symbols.remote_provider": (None, Mode.ADVANCED),
    "engines.pinned_pack": (None, Mode.ADVANCED),
    "privacy.include_sensitive_in_exports": (False, Mode.ADVANCED),
    "retention.quarantine_days": (30, Mode.ADVANCED),
    "retention.log_budget_bytes": (1024**3, Mode.ADVANCED),
    "workers.heavy": (1, Mode.ADVANCED),
    "workers.memory_budget_fraction": (0.70, Mode.ADVANCED),
    # scientific parameters: changing them can invalidate comparability (ACET-MODE-001)
    "calibration.min_samples": (30, Mode.RESEARCH),
    "matching.thresholds": (None, Mode.RESEARCH),
    "baseline.min_history": (5, Mode.RESEARCH),
    "telemetry.enabled": (False, Mode.DEVELOPER),
}


def get_setting(ws: Workspace, key: str) -> Any:
    if key not in SETTINGS:
        raise AcetError("ACET-PROF-001", f"unknown setting {key}")
    row = ws.db.conn.execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(row[0]) if row else SETTINGS[key][0]


def current_mode(ws: Workspace) -> Mode:
    return Mode(get_setting(ws, "ui.mode"))


def set_setting(ws: Workspace, key: str, value: Any) -> None:
    ws.require_writable()
    if key not in SETTINGS:
        raise AcetError("ACET-PROF-001", f"unknown setting {key}")
    required = SETTINGS[key][1]
    mode = current_mode(ws)
    if key != "ui.mode" and RANK[mode] < RANK[required]:
        raise AcetError("ACET-PROF-001", f"{key} requires {required.value} mode (current: {mode.value})")
    if key == "ui.mode":
        Mode(value)
    if key.startswith("secret") or (isinstance(value, str) and value.lower().startswith(("token", "secret"))):
        raise AcetError(
            "ACET-PROF-001", "secrets are stored in the OS credential store, never in settings (ACET-SEC-006)"
        )
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO settings(key, value_json, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET"
            " value_json=excluded.value_json, updated_at=excluded.updated_at",
            (key, stable_json(value).decode(), utc_now_iso()),
        )
        repo.audit(tx, "settings.set", "settings", key, {"mode": mode.value})


def effective_settings(ws: Workspace) -> dict[str, Any]:
    return {k: get_setting(ws, k) for k in sorted(SETTINGS)}
