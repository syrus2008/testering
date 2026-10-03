"""Canonical report model (spec §42, ACET-CLOSE-004, ACC-021/016/028/040).

Executive and Technical renderings derive from this one structure. Probabilities
are always null (no validated calibration for V1 outputs); no global score.
Strings and PDB paths are excluded unless explicitly requested (ACET-PRI-002).
"""

from __future__ import annotations

import json
from typing import Any

import acet
from acet.application.workspace import Workspace
from acet.domain.error_codes import AcetError
from acet.domain.jsonschema import validate_named
from acet.domain.timeutil import utc_now_iso
from acet.engines.quirks import load_known_limitations
from acet.reporting import vocabulary as voc
from acet.storage import repositories as repo

INFERENCE = voc.DECISION_INFERENCE
MATCHER_ENGINE = "acet.featurematch"


def _calibration_state(ws: Workspace, sha: str) -> dict[str, Any]:
    """Whether a validated calibration covers this artifact's analysis context (ACC-147). Reports
    always print classes; this only tells the reader whether the context is in or out of distribution."""
    from acet.analysis.results import derived_for_artifact
    from acet.benchmark.context import analysis_context, context_key

    rows = ws.db.conn.execute(
        "SELECT context_key FROM calibration_profile WHERE engine=? AND validated=1", (MATCHER_ENGINE,)
    ).fetchall()
    if not rows:
        state = "UNCALIBRATED"
        key = None
    else:
        size = ws.db.conn.execute("SELECT size_bytes FROM artifact WHERE sha256=?", (sha,)).fetchone()
        key = context_key(
            analysis_context(
                derived_for_artifact(ws, "acet.pe", sha),
                derived_for_artifact(ws, "acet.features", sha),
                size[0] if size else None,
                derived_for_artifact(ws, "ghidra.extract", sha),
            )
        )
        state = "CALIBRATED" if any(r["context_key"] == key for r in rows) else "OUT_OF_DISTRIBUTION"
    return {"engine": MATCHER_ENGINE, "state": state, "context_key": key, "text": voc.CALIBRATION_TEXT[state]}


def _lineage_section(ws: Workspace, product_id: str, left: str, right: str) -> dict[str, Any] | None:
    """Lineage events of the compared transition (left → right) from the latest lineage run covering it."""
    runs = ws.db.conn.execute(
        "SELECT id, status, input_hashes_json, resolved_config_json FROM analysis_run WHERE scope_type='lineage'"
        " AND scope_id=? ORDER BY seq DESC",
        (product_id,),
    ).fetchall()
    lr = None
    for r in runs:
        b = json.loads(r["input_hashes_json"] or "{}").get("builds") or []
        if left in b and right in b and b.index(right) == b.index(left) + 1:
            lr = r
            break
    if lr is None:
        return {
            "run_id": None,
            "status": "NOT_COMPUTED",
            "note": "No lineage run covers this transition; lineage evidence is missing, not negative.",
            "summary": {},
            "events": [],
        }
    rules = json.loads(lr["resolved_config_json"] or "{}").get("rules")
    events = []
    for a in ws.db.conn.execute(
        "SELECT la.*, fi.address, fi.name, fi.artifact_sha256 FROM lineage_assignment la JOIN function_instance fi"
        " ON fi.id=la.function_instance_id WHERE la.analysis_run_id=? AND la.build_id=? ORDER BY la.rowid",
        (lr["id"], right),
    ):
        ev = json.loads(a["evidence_json"] or "{}")
        view = voc.lineage_event_view(a["relation"], ev)
        historical = {
            "RESURRECTED_CONFIRMED": a["lineage_id"],
            "RESURRECTED_CANDIDATE": ev.get("previous_lineage"),
            "SPLIT_PARENT": ev.get("parent"),
        }.get(a["relation"])
        events.append(
            {
                "lineage_id": a["lineage_id"],
                "historical_lineage_id": historical,
                "relation": a["relation"],
                "instance": {
                    "function_instance_id": a["function_instance_id"],
                    "artifact": a["artifact_sha256"],
                    "address": a["address"],
                    "name": a["name"],
                    "build_id": a["build_id"],
                    "component_role": a["component_role"],
                },
                **view,
                "decision": ev.get("decision") or ev.get("status"),
                "provenance": {
                    "lineage_run_id": lr["id"],
                    "lineage_rules": rules,
                    "compare_run_id": ev.get("compare_run"),
                    "assignment_status": a["status"],
                },
            }
        )
    by_rel: dict[str, int] = {}
    by_inf: dict[str, int] = {}
    for e in events:
        by_rel[e["relation"]] = by_rel.get(e["relation"], 0) + 1
        by_inf[e["inference_state"]] = by_inf.get(e["inference_state"], 0) + 1
    return {
        "run_id": lr["id"],
        "status": lr["status"],
        "rules": rules,
        "summary": {
            "relations": dict(sorted(by_rel.items())),
            "inference_states": dict(sorted(by_inf.items())),
            "resurrections_confirmed": by_rel.get("RESURRECTED_CONFIRMED", 0),
            "resurrection_candidates": by_rel.get("RESURRECTED_CANDIDATE", 0),
        },
        "events": events,
    }


def _run_info(ws: Workspace, run_id: str) -> dict[str, Any]:
    r = ws.db.conn.execute("SELECT * FROM analysis_run WHERE id=?", (run_id,)).fetchone()
    if r is None:
        raise AcetError("ACET-NOTFOUND-001", f"run {run_id}")
    cfg = json.loads(r["resolved_config_json"] or "{}")
    prs = [
        dict(x)
        for x in ws.db.conn.execute(
            "SELECT processor_id, processor_version, status, outcome, cache_key, input_hash, config_hash, termination,"
            " completion_state, determinism_class FROM processor_run WHERE analysis_run_id=? ORDER BY rowid",
            (run_id,),
        )
    ]
    return {
        "run_id": r["id"],
        "scope_type": r["scope_type"],
        "scope_id": r["scope_id"],
        "status": r["status"],
        "coverage": {"state": "MEASURED" if r["coverage"] is not None else "NOT_MEASURED", "value": r["coverage"]},
        "started_at": r["started_at"],
        "finished_at": r["finished_at"],
        "acet_version": r["acet_version"],
        "profile": cfg.get("profile"),
        "engines": cfg.get("engines"),
        "resolved_config_hash": r["resolved_config_hash"],
        "input_hashes": json.loads(r["input_hashes_json"] or "[]"),
        "missing_evidence": json.loads(r["missing_evidence_json"] or "[]"),
        "warnings": json.loads(r["warnings_json"] or "[]"),
        "processor_runs": prs,
    }


def compare_report(ws: Workspace, run_id: str, *, include_sensitive: bool = False) -> dict[str, Any]:
    run = _run_info(ws, run_id)
    if run["scope_type"] != "compare":
        raise AcetError("ACET-IMP-005", "compare_report needs a compare run")
    left, right = run["scope_id"].split(":")
    comps = []
    for side, b in (("left", left), ("right", right)):
        bi = ws.db.conn.execute(
            "SELECT b.*, r.version_label FROM build b LEFT JOIN release r ON r.id=b.release_id WHERE b.id=?", (b,)
        ).fetchone()
        comps.append(
            {
                "side": side,
                "build_id": b,
                "release": bi["version_label"],
                "status": bi["status"],
                "fingerprint": bi["build_fingerprint"],
                "components": [
                    {k: c[k] for k in ("role", "label", "sha256", "size_bytes", "format", "integrity_state")}
                    for c in repo.build_artifacts(ws.db.conn, b)
                ],
            }
        )
    calib = {c["sha256"]: _calibration_state(ws, c["sha256"]) for c in comps[0]["components"]}
    names = {
        r["id"]: r["name"]
        for r in ws.db.conn.execute(
            "SELECT id, name FROM function_instance WHERE artifact_sha256 IN (SELECT left_artifact_sha256 FROM consensus_match"
            " WHERE analysis_run_id=? UNION SELECT right_artifact_sha256 FROM consensus_match WHERE analysis_run_id=?)",
            (run_id, run_id),
        )
    }
    functions = []
    counts: dict[str, int] = {}
    for c in ws.db.conn.execute(
        "SELECT * FROM consensus_match WHERE analysis_run_id=? ORDER BY left_artifact_sha256, rowid", (run_id,)
    ):
        ev = json.loads(c["evidence_json"])
        counts[c["decision"]] = counts.get(c["decision"], 0) + 1
        functions.append(
            {
                "left_artifact": c["left_artifact_sha256"],
                "right_artifact": c["right_artifact_sha256"],
                "left_address": ev.get("left_address"),
                "right_address": ev.get("right_address"),
                "left_name": names.get(c["left_function_id"]),
                "right_name": names.get(c["right_function_id"]),
                "decision": c["decision"],
                "inference_state": INFERENCE[c["decision"]],
                "strength_class": c["strength_class"],
                "evidence_diversity": c["evidence_diversity"],
                "engine_count": c["engine_count"],
                "probability": None,
                "confidence": {
                    "display": "class",
                    "calibration_state": (calib.get(c["left_artifact_sha256"]) or {}).get("state", "UNCALIBRATED"),
                },
                "supporting_families": ev.get("supporting_families") or [],
                "contradicting": len(ev.get("contradicting_evidence") or []),
                "side": ev.get("side", "pair"),
            }
        )
    changes = []
    events: list[dict[str, Any]] = []
    for d in ws.db.conn.execute(
        "SELECT * FROM detected_change WHERE analysis_run_id=? ORDER BY component_role, dimension", (run_id,)
    ):
        ev = json.loads(d["evidence_json"])
        metrics = ev.get("metrics", {})
        if not include_sensitive:
            metrics = {k: v for k, v in metrics.items() if not k.startswith("strings_")}
        if d["dimension"] == "ECOSYSTEM":
            events = metrics.get("correlated_events", [])
        changes.append(
            {
                "component_role": d["component_role"],
                "dimension": d["dimension"],
                "measurement": {"state": d["measurement_state"], "value": metrics},
                "severity_class": d["severity_class"],
                "reliability_class": d["reliability_class"],
                "baseline": ev.get("baseline"),
                "notes": ev.get("notes", []),
            }
        )
    prod = ws.db.conn.execute("SELECT product_id FROM build WHERE id=?", (left,)).fetchone()["product_id"]
    lineage = _lineage_section(ws, prod, left, right)
    unresolved_left = sum(1 for f in functions if f["side"] == "pair" and f["decision"] == "UNRESOLVED")
    unresolved_right = sum(1 for f in functions if f["side"] == "right-only")
    head = [
        f"Comparison {comps[0]['release'] or left[:8]} → {comps[1]['release'] or right[:8]}: run {run['status']}, "
        f"coverage {run['coverage']['value']}.",
        "Function decisions: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ".",
        f"{unresolved_left} function(s) without a counterpart and {unresolved_right} new-side function(s) "
        "remain UNRESOLVED; they are not classified as removed or new.",
    ]
    ls = (lineage or {}).get("summary") or {}
    if ls.get("resurrections_confirmed") or ls.get("resurrection_candidates"):
        head.append(
            f"Lineage: {ls.get('resurrections_confirmed', 0)} resurrection(s) confirmed by rule (historical identity "
            f"reused on converging evidence); {ls.get('resurrection_candidates', 0)} resurrection candidate(s) remain "
            "hypotheses — not established."
        )
    if (lineage or {}).get("status") == "NOT_COMPUTED":
        head.append("Lineage was not computed for this transition (missing evidence, not a negative result).")
    unusual = [c for c in changes if c["severity_class"] in ("UNUSUAL", "EXTREME")]
    if unusual:
        head.append(
            "Unusual dimensions: " + ", ".join(sorted({f"{c['component_role']}/{c['dimension']}" for c in unusual}))
        )
    unc = ["Confidence is shown as classes; no probability is displayed without validated calibration (ADR-0008)."]
    if run["missing_evidence"]:
        unc.append("Missing evidence: " + ", ".join(sorted({m["processor"] for m in run["missing_evidence"]})))
    unverified = [
        k
        for k, v in ((run["engines"] or {}).get("providers") or {}).items()
        if v.get("available") and not v.get("verified")
    ]
    if unverified:
        unc.append("Unverified engines: " + ", ".join(sorted(unverified)))
    for comp_sha, cs in sorted(calib.items()):
        if cs["state"] != "CALIBRATED":
            unc.append(f"Calibration for {comp_sha[:12]}: {cs['text']}.")
    if events:
        unc.append(f"{len(events)} external event(s): {voc.TEMPORAL_CORRELATION}.")
    completeness = voc.completeness(run["status"], run["missing_evidence"])
    providers = {p for p, v in ((run["engines"] or {}).get("providers") or {}).items() if v.get("available")}
    report = {
        "schema_version": 1,
        "kind": "acet-report",
        "generated_at": utc_now_iso(),
        "acet_version": acet.__version__,
        "scope": {"type": "compare", "id": run_id},
        "executive": {
            "headline": head,
            "uncertainty": unc,
            "no_global_score": True,
            "completeness": completeness,
        },
        "technical": {
            "runs": [run],
            "components": comps,
            "functions": functions,
            "changes": changes,
            "lineage": lineage,
            "missing_evidence": run["missing_evidence"],
            "external_events": [{**e, "interpretation": voc.TEMPORAL_CORRELATION} for e in events],
            "calibration": list(calib.values()),
        },
        "provenance": {
            "profiles": [run["profile"]],
            "engines": run["engines"],
            "config_hashes": [run["resolved_config_hash"]],
            "input_hashes": run["input_hashes"],
        },
        "limitations": [k.__dict__ for k in load_known_limitations() if k.provider_id in providers],
        "sensitive_content_included": include_sensitive,
    }
    validate_named(report, "report")
    problems = voc.invariant_problems(report)
    if problems:  # a model that overstates its evidence is a bug, never a report
        raise AcetError("ACET-INT-001", "report invariants violated: " + "; ".join(problems))
    return report
