"""Product timeline (spec §31, §35): builds, observations, releases, external events, change summaries.

Single indexed queries; no heavy recomputation (§106: 100 builds without synchronous heavy work).
"""

from __future__ import annotations

from typing import Any

from acet.application.workspace import Workspace


def product_timeline(ws: Workspace, product_id: str) -> list[dict[str, Any]]:
    conn = ws.db.conn
    items: list[dict[str, Any]] = []
    for r in conn.execute(
        "SELECT o.observed_at, o.time_precision, o.source_type, b.id AS build_id, b.status, r.version_label, r.channel"
        " FROM observation o JOIN build b ON b.id=o.build_id LEFT JOIN release r ON r.id=b.release_id"
        " WHERE b.product_id=? AND b.deleted_at IS NULL",
        (product_id,),
    ):
        items.append(
            {
                "kind": "observation",
                "at": r["observed_at"],
                "precision": r["time_precision"],
                "build_id": r["build_id"],
                "release": r["version_label"],
                "channel": r["channel"],
                "build_status": r["status"],
            }
        )
    for r in conn.execute("SELECT * FROM external_event WHERE product_id=?", (product_id,)):
        items.append(
            {
                "kind": "external_event",
                "at": r["occurred_at"],
                "precision": r["time_precision"],
                "event_type": r["event_type"],
                "summary": r["summary"],
                "source_class": r["source_class"],
                "relation": "context only; correlation is not causation",
            }
        )
    for r in conn.execute(
        "SELECT ar.id, ar.scope_id, ar.status, (SELECT min(observed_at) FROM observation o WHERE"
        " o.build_id = substr(ar.scope_id, instr(ar.scope_id, ':') + 1)) AS at,"
        " (SELECT count(*) FROM detected_change dc WHERE dc.analysis_run_id=ar.id AND dc.severity_class IN"
        " ('UNUSUAL','EXTREME')) AS unusual FROM analysis_run ar JOIN build b ON b.id = substr(ar.scope_id, 1,"
        " instr(ar.scope_id, ':') - 1) WHERE ar.scope_type='compare' AND b.product_id=?",
        (product_id,),
    ):
        items.append(
            {
                "kind": "comparison",
                "at": r["at"],
                "run_id": r["id"],
                "status": r["status"],
                "unusual_dimensions": r["unusual"],
            }
        )
    return sorted(items, key=lambda x: (x["at"] is None, x["at"] or "", x["kind"]))
