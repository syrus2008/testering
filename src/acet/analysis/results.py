"""Read-side helpers for validated derived results."""

from __future__ import annotations

import json
from typing import Any

from acet.application.workspace import Workspace


def derived_for_artifact(ws: Workspace, processor_id: str, sha: str) -> dict[str, Any] | None:
    """Latest CURRENT (else INCOMPLETE) result of an artifact-level processor, directly or via its upstream."""
    row = ws.db.conn.execute(
        "SELECT dr.output_relpath FROM derived_result dr JOIN derived_input di ON di.derived_result_id=dr.id"
        " WHERE dr.processor_id=? AND di.input_kind='artifact' AND di.input_ref=? AND dr.state IN ('CURRENT','INCOMPLETE')"
        " ORDER BY dr.state='CURRENT' DESC, dr.created_at DESC LIMIT 1",
        (processor_id, sha),
    ).fetchone()
    if row is None:  # e.g. acet.features takes the ghidra export (derived) as input
        row = ws.db.conn.execute(
            "SELECT dr.output_relpath FROM derived_result dr JOIN derived_input di ON di.derived_result_id=dr.id"
            " JOIN derived_input up ON up.derived_result_id=di.input_ref"
            " WHERE dr.processor_id=? AND di.input_kind='derived' AND up.input_kind='artifact' AND up.input_ref=?"
            " AND dr.state IN ('CURRENT','INCOMPLETE') ORDER BY dr.state='CURRENT' DESC, dr.created_at DESC LIMIT 1",
            (processor_id, sha),
        ).fetchone()
    if row is None:
        return None
    data: dict[str, Any] = json.loads((ws.path / row["output_relpath"] / "result.json").read_text(encoding="utf-8"))
    return data
