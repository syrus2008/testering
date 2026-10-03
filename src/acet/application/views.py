"""Read models for the UI (headless, testable; ACET-ARCH-001). Pure queries, no Qt."""

from __future__ import annotations

import json
import shutil
from typing import Any

from acet.application.workspace import Workspace


def _rows(ws: Workspace, sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(r) for r in ws.db.conn.execute(sql, args)]


def products(ws: Workspace) -> list[dict[str, Any]]:
    return _rows(
        ws,
        "SELECT p.id, p.name, p.vendor, p.created_at, (SELECT count(*) FROM build b WHERE b.product_id=p.id"
        " AND b.deleted_at IS NULL) AS builds FROM product p ORDER BY p.name",
    )


def builds(ws: Workspace, product_id: str | None = None) -> list[dict[str, Any]]:
    from acet.application.builds import list_builds

    return list_builds(ws, product_id)


def runs(ws: Workspace, scope_like: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT id, scope_type, scope_id, status, coverage, started_at, finished_at FROM analysis_run"
    if scope_like:
        return _rows(ws, sql + " WHERE scope_id LIKE ? ORDER BY seq DESC", (f"%{scope_like}%",))
    return _rows(ws, sql + " ORDER BY seq DESC")


def dashboard(ws: Workspace) -> dict[str, Any]:
    usage = shutil.disk_usage(ws.path)
    blob_bytes = ws.db.conn.execute(
        "SELECT coalesce(sum(size_bytes),0) FROM artifact WHERE integrity_state='AVAILABLE'"
    ).fetchone()[0]
    return {
        "products": products(ws),
        "recent_builds": builds(ws)[-10:][::-1],
        "active_jobs": _rows(
            ws,
            "SELECT id, job_type, state, stage, progress FROM job WHERE state NOT IN"
            " ('COMPLETED','CANCELLED','FAILED_PERMANENT') ORDER BY seq DESC",
        ),
        "storage": {"artifact_bytes": blob_bytes, "free_bytes": usage.free, "workspace": ws.name},
        "recent_changes": _rows(
            ws,
            "SELECT dc.analysis_run_id, dc.component_role, dc.dimension, dc.severity_class,"
            " dc.reliability_class FROM detected_change dc WHERE dc.severity_class IN"
            " ('UNUSUAL','EXTREME') ORDER BY dc.rowid DESC LIMIT 20",
        ),
    }


def functions_for_run(ws: Workspace, run_id: str) -> list[dict[str, Any]]:
    names = {
        r["id"]: r["name"]
        for r in ws.db.conn.execute(
            "SELECT fi.id, fi.name FROM function_instance fi WHERE fi.id IN (SELECT left_function_id FROM consensus_match"
            " WHERE analysis_run_id=? UNION SELECT right_function_id FROM consensus_match WHERE analysis_run_id=?)",
            (run_id, run_id),
        )
    }
    roles = {
        r["sha256"]: r["role"]
        for r in ws.db.conn.execute(
            "SELECT ca.artifact_sha256 AS sha256, c.role FROM component c JOIN component_artifact ca ON"
            " ca.component_id=c.id"
        )
    }
    out = []
    for r in ws.db.conn.execute("SELECT * FROM consensus_match WHERE analysis_run_id=? ORDER BY rowid", (run_id,)):
        ev = json.loads(r["evidence_json"])
        out.append(
            {
                "id": r["id"],
                "component": roles.get(r["right_artifact_sha256"], "?"),
                "left_address": ev.get("left_address"),
                "left_name": names.get(r["left_function_id"]),
                "right_address": ev.get("right_address"),
                "right_name": names.get(r["right_function_id"]),
                "decision": r["decision"],
                "strength_class": r["strength_class"],
                "evidence_diversity": r["evidence_diversity"],
                "engine_count": r["engine_count"],
                "families": ", ".join(ev.get("supporting_families") or []),
            }
        )
    return out


def evidence(ws: Workspace, consensus_id: str) -> dict[str, Any]:
    r = ws.db.conn.execute("SELECT * FROM consensus_match WHERE id=?", (consensus_id,)).fetchone()
    if r is None:
        return {}
    ev = json.loads(r["evidence_json"])
    raw = _rows(
        ws,
        "SELECT engine, engine_version, raw_score, decision, families_json FROM matcher_result WHERE"
        " analysis_run_id=? AND left_function_id IS ? ORDER BY engine",
        (r["analysis_run_id"], r["left_function_id"]),
    )
    return {
        "decision": r["decision"],
        "strength_class": r["strength_class"],
        "evidence_diversity": r["evidence_diversity"],
        "engine_count": r["engine_count"],
        "rules": r["rules"],
        "probability": None,
        "supporting_evidence": ev.get("supporting_evidence"),
        "contradicting_evidence": ev.get("contradicting_evidence"),
        "missing_evidence": ev.get("missing_evidence"),
        "raw_engine_results": raw,
        "notes": ev.get("notes"),
    }


def lineages(ws: Workspace, product_id: str) -> list[dict[str, Any]]:
    run = ws.db.conn.execute(
        "SELECT id FROM analysis_run WHERE scope_type='lineage' AND scope_id=? ORDER BY seq DESC LIMIT 1", (product_id,)
    ).fetchone()
    if run is None:
        return []
    return _rows(
        ws,
        "SELECT l.id, l.component_role, coalesce(l.label, (SELECT fi.name FROM lineage_assignment la JOIN"
        " function_instance fi ON fi.id=la.function_instance_id WHERE la.lineage_id=l.id AND fi.name IS NOT"
        " NULL LIMIT 1)) AS label, count(la.id) AS instances, group_concat(DISTINCT la.relation) AS relations,"
        " min(la.rowid) AS first FROM lineage l JOIN lineage_assignment la ON la.lineage_id=l.id WHERE"
        " la.analysis_run_id=? GROUP BY l.id ORDER BY first",
        (run["id"],),
    )


def changes(ws: Workspace, run_id: str) -> list[dict[str, Any]]:
    out = []
    for r in ws.db.conn.execute(
        "SELECT * FROM detected_change WHERE analysis_run_id=? ORDER BY component_role, dimension", (run_id,)
    ):
        ev = json.loads(r["evidence_json"])
        out.append(
            {
                "component": r["component_role"],
                "dimension": r["dimension"],
                "state": r["measurement_state"],
                "severity": r["severity_class"],
                "reliability": r["reliability_class"],
                "summary": json.dumps(ev.get("metrics"), ensure_ascii=False)[:200],
                "notes": "; ".join(ev.get("notes", [])),
            }
        )
    return out


def jobs(ws: Workspace) -> list[dict[str, Any]]:
    from acet.jobs.store import list_jobs

    return list_jobs(ws.db)
