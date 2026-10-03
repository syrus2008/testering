"""Reproduce an analysis run with its exact Engine Pack (spec §46, ACET-UPD-002/005, ACC-062)."""

from __future__ import annotations

import json
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.error_codes import AcetError
from acet.engines.environment import EngineEnvironment, detect
from acet.platform.engine_packs import installed_packs, provider_overrides


def engine_environment_for_run(ws: Workspace, run_id: str) -> EngineEnvironment:
    """The environment of the Engine Pack the run used; refuses a substitute (no silent engine change)."""
    row = ws.db.conn.execute(
        "SELECT ep.name, ep.manifest_json FROM analysis_run ar JOIN engine_pack ep ON"
        " ep.id=ar.engine_pack_id WHERE ar.id=?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise AcetError("ACET-NOTFOUND-001", f"run {run_id} has no recorded engine pack")
    pack_ref = row["name"]
    if pack_ref == "local-detected":
        manifest: dict[str, Any] = json.loads(row["manifest_json"])
        current = detect().manifest()
        if current["providers"] != manifest["providers"]:
            raise AcetError("ACET-UPD-001", "the run used locally detected engines that differ from the current ones")
        return detect()
    pid, _, ver = pack_ref.partition("@")
    for p in installed_packs():
        if p["id"] == pid and p["version"] == ver:
            if p["revoked"]:
                raise AcetError("ACET-UPD-001", f"engine pack {pack_ref} is revoked (history kept, no new runs)")
            return detect(provider_overrides(p), pack_id=pack_ref)
    raise AcetError("ACET-UPD-001", f"engine pack {pack_ref} used by this run is not installed")
