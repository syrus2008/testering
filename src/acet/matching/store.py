"""Index function instances, matcher results and consensus into SQLite (spec §9, ACET-MAT-003)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from acet.analysis.registry import ProcessorSpec
from acet.application.workspace import Workspace
from acet.domain.canonical import stable_json
from acet.domain.ids import uuid7


def _load(out: Path) -> Any:
    return json.loads((out / "result.json").read_text(encoding="utf-8"))


def ingest_functions(
    ws: Workspace,
    run_id: str,
    spec: ProcessorSpec,
    artifacts: tuple[str, ...],
    derived_id: str,
    out: Path,
    prid: str | None,
) -> None:
    conn = ws.db.conn
    if conn.execute("SELECT 1 FROM function_instance WHERE derived_result_id=? LIMIT 1", (derived_id,)).fetchone():
        return  # idempotent: facts of a derived result are indexed once (INV-004)
    data = _load(out)
    producer = (
        prid
        or conn.execute("SELECT produced_by_processor_run_id FROM derived_result WHERE id=?", (derived_id,)).fetchone()[
            0
        ]
    )
    with ws.db.transaction() as tx:
        for f in data["functions"]:
            tx.execute(
                "INSERT INTO function_instance(id, artifact_sha256, extractor_run_id, address, size, name,"
                " normalized_hash, feature_schema_version, normalizer_version, derived_result_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    uuid7(),
                    artifacts[0],
                    producer,
                    f["entry"],
                    f["size"],
                    f["identity"]["name"],
                    f["instruction"]["normalized_hash"],
                    data["feature_schema_version"],
                    data["normalizer_version"],
                    derived_id,
                ),
            )


def function_ids(ws: Workspace, sha: str) -> dict[int, str]:
    """Address → function_instance id, using the CURRENT normalized view of that artifact."""
    rows = ws.db.conn.execute(
        "SELECT fi.address, fi.id FROM function_instance fi JOIN derived_result dr ON dr.id=fi.derived_result_id"
        " WHERE fi.artifact_sha256=? AND dr.state IN ('CURRENT','INCOMPLETE') ORDER BY dr.created_at",
        (sha,),
    ).fetchall()
    return {int(r["address"]): str(r["id"]) for r in rows}


def ingest_matcher(
    ws: Workspace,
    run_id: str,
    spec: ProcessorSpec,
    artifacts: tuple[str, ...],
    derived_id: str,
    out: Path,
    prid: str | None,
) -> None:
    conn = ws.db.conn
    if conn.execute(
        "SELECT 1 FROM matcher_result WHERE analysis_run_id=? AND engine=? AND left_artifact_sha256=?"
        " AND right_artifact_sha256=? LIMIT 1",
        (run_id, _engine(spec), artifacts[0], artifacts[1]),
    ).fetchone():
        return
    data = _load(out)
    lf, rf = function_ids(ws, artifacts[0]), function_ids(ws, artifacts[1])
    with ws.db.transaction() as tx:
        for p in data["pairs"]:
            tx.execute(
                "INSERT INTO matcher_result(id, analysis_run_id, engine, engine_version, left_function_id,"
                " right_function_id, raw_score, calibrated_strength, decision, evidence_json, left_artifact_sha256,"
                " right_artifact_sha256, families_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    uuid7(),
                    run_id,
                    data["engine"],
                    data["engine_version"],
                    lf.get(p["left"]),
                    rf.get(p.get("right")),
                    p.get("raw_score"),
                    None,
                    p["decision"],
                    stable_json(p).decode(),
                    artifacts[0],
                    artifacts[1],
                    stable_json(sorted({e["family"] for e in p.get("evidence", [])})).decode(),
                ),
            )


def _engine(spec: ProcessorSpec) -> str:
    return {
        "acet.featurematch": "acet.featurematch",
        "ghidriff.diff": "ghidriff",
        "bindiff.diff": "bindiff",
        "qbindiff.diff": "qbindiff",
    }.get(spec.id, spec.id)


def ingest_consensus(
    ws: Workspace,
    run_id: str,
    spec: ProcessorSpec,
    artifacts: tuple[str, ...],
    derived_id: str,
    out: Path,
    prid: str | None,
) -> None:
    conn = ws.db.conn
    if conn.execute(
        "SELECT 1 FROM consensus_match WHERE analysis_run_id=? AND left_artifact_sha256=? AND"
        " right_artifact_sha256=? LIMIT 1",
        (run_id, artifacts[0], artifacts[1]),
    ).fetchone():
        return
    data = _load(out)
    lf, rf = function_ids(ws, artifacts[0]), function_ids(ws, artifacts[1])
    with ws.db.transaction() as tx:
        for m in data["matches"]:
            ev = {
                k: m.get(k)
                for k in (
                    "supporting_evidence",
                    "contradicting_evidence",
                    "missing_evidence",
                    "supporting_families",
                    "alternatives",
                    "notes",
                    "merge_candidate",
                    "candidates",
                )
            }
            ev["left_address"], ev["right_address"] = m["left"], m["right"]
            tx.execute(
                "INSERT INTO consensus_match(id, analysis_run_id, left_artifact_sha256, right_artifact_sha256,"
                " left_function_id, right_function_id, decision, strength_class, evidence_diversity, engine_count,"
                " evidence_json, calibration_profile_id, rules) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    uuid7(),
                    run_id,
                    artifacts[0],
                    artifacts[1],
                    lf.get(m["left"]),
                    rf.get(m["right"]) if m["right"] is not None else None,
                    m["decision"],
                    m["strength_class"],
                    m["evidence_diversity"],
                    m["engine_count"],
                    stable_json(ev).decode(),
                    data["calibration_profile_id"],
                    data["rules"],
                ),
            )
        for u in data["unmatched_right"]:
            tx.execute(
                "INSERT INTO consensus_match(id, analysis_run_id, left_artifact_sha256, right_artifact_sha256,"
                " left_function_id, right_function_id, decision, strength_class, evidence_diversity, engine_count,"
                " evidence_json, calibration_profile_id, rules) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    uuid7(),
                    run_id,
                    artifacts[0],
                    artifacts[1],
                    None,
                    rf.get(u["right"]),
                    "UNRESOLVED",
                    "LOW",
                    0,
                    0,
                    stable_json(
                        {
                            "right_address": u["right"],
                            "candidates": u["candidates"],
                            "notes": u["notes"],
                            "side": "right-only",
                        }
                    ).decode(),
                    None,
                    data["rules"],
                ),
            )
