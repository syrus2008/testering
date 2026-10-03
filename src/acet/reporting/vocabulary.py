"""Inference vocabulary shared by the report model, every renderer and the UI (spec §42, ADR-0008, ADR-0012).

The model decides the inference level and the wording of every claim; renderers and UI widgets only
transcribe ``inference_state`` / ``status_text`` / ``explanation`` and never recompute them. That is
what lets the tests check that no rendering states a claim more strongly than the model does.
"""

from __future__ import annotations

from typing import Any

# Ordered from weakest to strongest. A rendering may weaken (e.g. omit) a claim, never strengthen it.
INFERENCE_RANK = {
    "NOT_OBSERVED": 0,
    "UNRESOLVED": 0,
    "ABSTAIN": 0,
    "HYPOTHESIS": 1,
    "AMBIGUOUS": 1,
    "CONFLICTING": 1,
    "PROBABLE": 2,
    "STRONG": 3,
    "CONFIRMED_BY_RULE": 4,
}

DECISION_INFERENCE = {
    "EXACT": "CONFIRMED_BY_RULE",
    "STRONG": "STRONG",
    "PROBABLE": "PROBABLE",
    "AMBIGUOUS": "AMBIGUOUS",
    "CONFLICT": "CONFLICTING",
    "UNRESOLVED": "UNRESOLVED",
    "ABSTAIN": "ABSTAIN",
}

PARTIAL_TITLE = "PARTIAL RESULT — some evidence is missing"
PARTIAL_STATEMENT = (
    "Missing evidence is not negative evidence: what was not measured is unknown — not absent, not unchanged, "
    "not removed."
)
CANDIDATE_LABEL = "RESURRECTION CANDIDATE (hypothesis)"
CANDIDATE_TEXT = (
    "Hypothesis only: this function may be the return of a function seen earlier. The historical lineage was "
    "NOT reused; the two are linked for review."
)
UNRESOLVED_TEXT = "UNRESOLVED — origin unknown; not classified as new"
NOT_OBSERVED_TEXT = "Not observed in this build (DISAPPEARED) — absence is not proof of removal"
TEMPORAL_CORRELATION = "temporal correlation only, not a cause"
CALIBRATION_TEXT = {
    "UNCALIBRATED": "UNCALIBRATED — no validated calibration exists; confidence shown as classes",
    "OUT_OF_DISTRIBUTION": "OUT_OF_DISTRIBUTION (OOD) — no validated calibration covers this context; classes only",
    "CALIBRATED": "CALIBRATED context — reports still show classes (V1 reports never print probabilities)",
}

_FAMILY_TEXT = {
    "context": "caller context continuity",
    "data": "same data references",
    "name": "same symbol name",
    "rollback": "recorded rollback event",
}


def _families(ev: dict[str, Any]) -> tuple[list[str], list[str]]:
    return list(ev.get("supporting_families") or []), list(ev.get("contradicting_families") or [])


def lineage_event_view(relation: str, ev: dict[str, Any]) -> dict[str, Any]:
    """Inference level, rule and wording of one lineage assignment, from its stored evidence."""
    sup, con = _families(ev)
    reasons = list(ev.get("reasons") or [])
    if relation in ("CONTINUATION", "MODIFIED"):
        decision = ev.get("decision")
        inference = DECISION_INFERENCE.get(str(decision), "UNRESOLVED")
        verb = (
            "continues the lineage unchanged" if relation == "CONTINUATION" else "continues the lineage, code changed"
        )
        return {
            "inference_state": inference,
            "rule": "lineage@2 consensus join",
            "status_text": f"{relation}: {verb} (consensus {decision})",
            "explanation": None,
            "supporting_families": sup,
            "contradicting_families": con,
            "reasons": reasons,
        }
    if relation == "RESURRECTED_CONFIRMED":
        code = ev.get("code")
        why = [f"code {code}"] + [_FAMILY_TEXT.get(f, f) for f in sup]
        return {
            "inference_state": "CONFIRMED_BY_RULE",
            "rule": str(ev.get("rule") or "resurrect@2"),
            "status_text": "RESURRECTED_CONFIRMED: returns in its historical lineage",
            "explanation": (
                "Historical identity reused because independent evidence converges: "
                + ", ".join(why)
                + "; no contradicting family; unique pairing."
            ),
            "supporting_families": sup,
            "contradicting_families": con,
            "reasons": reasons,
        }
    if relation == "RESURRECTED_CANDIDATE":
        return {
            "inference_state": "HYPOTHESIS",
            "rule": str(ev.get("rule") or "resurrect@1"),
            "status_text": CANDIDATE_LABEL,
            "explanation": CANDIDATE_TEXT
            + (f" Supporting: {', '.join(sup)}." if sup else "")
            + (f" Not confirmed because: {'; '.join(reasons)}." if reasons else ""),
            "supporting_families": sup,
            "contradicting_families": con,
            "reasons": reasons,
        }
    if relation in ("SPLIT_PARENT", "MERGE_PARENT"):
        kind = "split" if relation == "SPLIT_PARENT" else "merge"
        return {
            "inference_state": "HYPOTHESIS",
            "rule": str(ev.get("rule") or f"{kind}@1"),
            "status_text": f"{relation}: {kind} inferred by rule (hypothesis; lineages linked, not merged)",
            "explanation": None,
            "supporting_families": sup,
            "contradicting_families": con,
            "reasons": reasons,
        }
    if relation == "DISAPPEARED":
        return {
            "inference_state": "NOT_OBSERVED",
            "rule": "lineage@2",
            "status_text": NOT_OBSERVED_TEXT,
            "explanation": None,
            "supporting_families": [],
            "contradicting_families": [],
            "reasons": [],
        }
    rejected = ev.get("rejected_resurrection")
    return {
        "inference_state": "UNRESOLVED",
        "rule": "lineage@2",
        "status_text": UNRESOLVED_TEXT,
        "explanation": (
            "A resurrection was considered and rejected: contradicting "
            + ", ".join(rejected.get("contradicting_families") or [])
            + "."
            if isinstance(rejected, dict)
            else None
        ),
        "supporting_families": [],
        "contradicting_families": list((rejected or {}).get("contradicting_families") or []),
        "reasons": list((rejected or {}).get("reasons") or []),
    }


RELATION_INFERENCE = {
    "RESURRECTED_CANDIDATE": {"HYPOTHESIS"},
    "SPLIT_PARENT": {"HYPOTHESIS"},
    "MERGE_PARENT": {"HYPOTHESIS"},
    "DISAPPEARED": {"NOT_OBSERVED"},
    "UNRESOLVED": {"UNRESOLVED"},
    "RESURRECTED_CONFIRMED": {"CONFIRMED_BY_RULE"},
    "CONTINUATION": set(DECISION_INFERENCE.values()),
    "MODIFIED": set(DECISION_INFERENCE.values()),
}


def invariant_problems(report: dict[str, Any]) -> list[str]:
    """Claims the canonical model must never make. Empty list = consistent."""
    out: list[str] = []
    te, ex = report["technical"], report["executive"]
    for f in te["functions"]:
        if f["inference_state"] != DECISION_INFERENCE[f["decision"]]:
            out.append(f"function decision {f['decision']} shown as {f['inference_state']}")
        if f.get("probability") is not None:
            out.append("a probability is printed")
    for e in (te.get("lineage") or {}).get("events", []):
        if e["inference_state"] not in RELATION_INFERENCE.get(e["relation"], set()):
            out.append(f"lineage {e['relation']} shown as {e['inference_state']}")
        if e["relation"] == "RESURRECTED_CANDIDATE" and "hypothesis" not in e["status_text"].lower():
            out.append("a resurrection candidate is not labelled as a hypothesis")
        if e["relation"] == "RESURRECTED_CONFIRMED" and "reused because" not in (e["explanation"] or ""):
            out.append("a confirmed resurrection does not explain why the historical identity was reused")
    for line in ex["headline"]:
        low = line.lower()
        if "candidate" in low and "hypothes" not in low:
            out.append(f"executive line states candidates without calling them hypotheses: {line!r}")
    comp = ex["completeness"]
    if comp["run_status"] == "COMPLETED_PARTIAL" and not comp["is_partial"]:
        out.append("a partial run is not flagged as partial")
    return out


def completeness(run_status: str, missing: list[dict[str, Any]]) -> dict[str, Any]:
    """The completeness block shown by the report and the UI for one analysis run."""
    partial = run_status == "COMPLETED_PARTIAL" or bool(missing)
    return {
        "run_status": run_status,
        "is_partial": partial,
        "title": PARTIAL_TITLE if partial else None,
        "missing": [
            {"processor": m.get("processor") or m.get("pair"), "outcome": m.get("outcome"), "reason": m.get("reason")}
            for m in missing
        ],
        "statement": PARTIAL_STATEMENT,
    }


def inspector_text(event: dict[str, Any]) -> str:
    """Evidence Inspector text for one lineage event (UI); same wording as the report."""
    lines = []
    if event["inference_state"] == "HYPOTHESIS":
        lines += ["⚠ HYPOTHESIS — NOT ESTABLISHED", ""]
    lines += [
        f"Statement:   {event['status_text']}",
        f"Relation:    {event['relation']}",
        f"Inference:   {event['inference_state']}",
        f"Rule:        {event['rule']}",
    ]
    if event.get("decision"):
        lines.append(f"Decision:    {event['decision']}")
    lines += [
        f"Supporting families:    {', '.join(event['supporting_families']) or '—'}",
        f"Contradicting families: {', '.join(event['contradicting_families']) or '—'}",
    ]
    if event.get("reasons"):
        lines += ["Reasons:"] + [f"  - {r}" for r in event["reasons"]]
    if event.get("explanation"):
        lines += ["", event["explanation"]]
    if event.get("historical_lineage_id"):
        lines.append(f"Historical lineage: {event['historical_lineage_id']}")
    prov = event.get("provenance") or {}
    if prov:
        lines += ["", "Provenance:"] + [f"  {k}: {v}" for k, v in sorted(prov.items()) if v is not None]
    return "\n".join(lines)
