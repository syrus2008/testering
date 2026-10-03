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
from acet.storage import repositories as repo

INFERENCE = {
    "EXACT": "CONFIRMED_BY_RULE",
    "STRONG": "STRONG",
    "PROBABLE": "PROBABLE",
    "AMBIGUOUS": "AMBIGUOUS",
    "CONFLICT": "CONFLICTING",
    "UNRESOLVED": "UNRESOLVED",
    "ABSTAIN": "ABSTAIN",
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
    lineage = None
    prod = ws.db.conn.execute("SELECT product_id FROM build WHERE id=?", (left,)).fetchone()["product_id"]
    lr = ws.db.conn.execute(
        "SELECT id, status FROM analysis_run WHERE scope_type='lineage' AND scope_id=? ORDER BY seq DESC LIMIT 1",
        (prod,),
    ).fetchone()
    if lr is not None:
        rel = dict(
            ws.db.conn.execute(
                "SELECT relation, count(*) FROM lineage_assignment WHERE analysis_run_id=? GROUP BY relation",
                (lr["id"],),
            ).fetchall()
        )
        links = dict(
            ws.db.conn.execute(
                "SELECT relation, count(*) FROM lineage_link WHERE analysis_run_id=? GROUP BY relation", (lr["id"],)
            ).fetchall()
        )
        lineage = {"run_id": lr["id"], "status": lr["status"], "relations": rel, "links": links}
    unresolved_left = sum(1 for f in functions if f["side"] == "pair" and f["decision"] == "UNRESOLVED")
    unresolved_right = sum(1 for f in functions if f["side"] == "right-only")
    head = [
        f"Comparison {comps[0]['release'] or left[:8]} → {comps[1]['release'] or right[:8]}: run {run['status']}, "
        f"coverage {run['coverage']['value']}.",
        "Function decisions: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ".",
        f"{unresolved_left} function(s) without a counterpart and {unresolved_right} new-side function(s) "
        "remain UNRESOLVED; they are not classified as removed or new.",
    ]
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
    if events:
        unc.append(f"{len(events)} external event(s) are temporal correlations, not causes.")
    providers = {p for p, v in ((run["engines"] or {}).get("providers") or {}).items() if v.get("available")}
    report = {
        "schema_version": 1,
        "kind": "acet-report",
        "generated_at": utc_now_iso(),
        "acet_version": acet.__version__,
        "scope": {"type": "compare", "id": run_id},
        "executive": {"headline": head, "uncertainty": unc, "no_global_score": True},
        "technical": {
            "runs": [run],
            "components": comps,
            "functions": functions,
            "changes": changes,
            "lineage": lineage,
            "missing_evidence": run["missing_evidence"],
            "external_events": events,
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
    return report
