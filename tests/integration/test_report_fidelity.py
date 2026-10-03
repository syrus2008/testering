"""Report fidelity: the inference vocabulary survives from the canonical model to every rendering,
and no renderer states a claim more strongly than the model (spec §42, ADR-0008, ADR-0012)."""

from __future__ import annotations

import csv
import html
import io
import json
import re
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from acet.benchmark import scenarios
from acet.changes.detector import detect_changes
from acet.changes.events import add_event
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso
from acet.reporting import vocabulary as voc
from acet.reporting.model import compare_report
from acet.reporting.render import to_csv, to_html, to_json, to_markdown

DATA = Path(__file__).resolve().parents[2] / "datasets" / "resurrection"


@pytest.fixture
def report(ws, monkeypatch) -> dict[str, Any]:
    """v2 → v3 of the heavy recompilation scenario (replay): a resurrection candidate, an UNRESOLVED
    function, a COMPLETED_PARTIAL run (no ghidriff), an out-of-distribution calibration context and an
    external event in the transition window."""
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DATA / "golden" / "ghidra"))
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON"):
        monkeypatch.delenv(k, raising=False)
    out = scenarios.run_scenario(ws, DATA, "recompiled_heavy")
    b = out["builds"]
    pid = ws.db.conn.execute("SELECT product_id FROM build WHERE id=?", (b[2],)).fetchone()[0]
    with ws.db.transaction() as tx:  # a calibration validated for *another* context → OOD here
        tx.execute(
            "INSERT INTO calibration_profile(id, engine, context_key, context_json, dataset_hash, split, method,"
            " mapping_json, metrics_json, validated, created_at) VALUES (?,?,?,?,?,?,?,?,?,1,?)",
            (
                uuid7(),
                "acet.featurematch",
                "other-context",
                "{}",
                "0" * 64,
                "test",
                "isotonic",
                "[[1.0, 0.9, 10]]",
                "{}",
                utc_now_iso(),
            ),
        )
    add_event(
        ws, pid, event_type="PATCH_NOTES", summary="vendor update announced", source_class="OFFICIAL",
        occurred_at="2001-01-02T12:00:00Z",
    )  # fmt: skip
    run = ws.db.conn.execute(
        "SELECT id FROM analysis_run WHERE scope_type='compare' AND scope_id=?", (f"{b[1]}:{b[2]}",)
    ).fetchone()[0]
    detect_changes(ws, run)
    return compare_report(ws, run)


def _md_table(md: str, header_start: str) -> list[list[str]]:
    lines = md.splitlines()
    i = next(n for n, line in enumerate(lines) if line.startswith(header_start))
    rows = []
    for line in lines[i + 2 :]:
        if not line.startswith("|"):
            break
        cells = re.split(r"(?<!\\)\|", line.strip())[1:-1]
        rows.append([c.strip().replace("\\|", "|") for c in cells])
    return rows


def _html_rows(doc: str, kind: str) -> list[str]:
    return re.findall(rf"<tr data-kind={kind}(?: data-relation=[A-Z_]+)? data-inference=([A-Z_]+)>", doc)


# ---------------------------------------------------------------------------------- survival
def test_vocabulary_survives_into_every_rendering(report):
    lin = report["technical"]["lineage"]
    assert [e["inference_state"] for e in lin["events"] if e["relation"] == "RESURRECTED_CANDIDATE"] == ["HYPOTHESIS"]
    assert report["executive"]["completeness"]["is_partial"]
    assert {f["confidence"]["calibration_state"] for f in report["technical"]["functions"]} == {"OUT_OF_DISTRIBUTION"}
    assert report["technical"]["external_events"]
    outputs = {"json": to_json(report), "md": to_markdown(report), "html": to_html(report)}
    for fmt, text in outputs.items():
        low = html.unescape(text).lower()
        for term in ("candidate", "hypothesis", "unresolved", "partial", "out_of_distribution", "ood",
                     "temporal correlation", "not negative evidence"):  # fmt: skip
            assert term in low, (fmt, term)
    rows = list(csv.DictReader(io.StringIO(to_csv(report))))
    assert {r["calibration_state"] for r in rows} == {"OUT_OF_DISTRIBUTION"}
    assert any(r["decision"] == "UNRESOLVED" and r["inference_state"] == "UNRESOLVED" for r in rows)


def test_partial_banner_comes_first_and_is_unmissable(report):
    md, doc = to_markdown(report), to_html(report)
    assert md.index("PARTIAL RESULT") < md.index("## Executive summary")
    assert doc.index("class=partial role=alert") < doc.index("<h2>Executive summary")
    assert "ghidriff" in md[: md.index("## Executive summary")]


def test_candidate_is_never_stated_as_a_fact(report):
    # Unit of reading: a Markdown line, an HTML row / list item / paragraph / heading.
    units = re.split(r"</tr>|</li>|</p>|</h\d>", to_html(report))
    doc = "\n".join(html.unescape(re.sub(r"<[^>]+>", " ", u)).replace("\n", " ") for u in units)
    for text in (to_markdown(report), doc, "\n".join(report["executive"]["headline"])):
        for line in text.splitlines():
            if "candidate" in line.lower():
                assert "hypothes" in line.lower(), line


def test_renderers_transcribe_inference_exactly(report):
    _assert_transcribed(report)


# -------------------------------------------------------------------------- no strengthening
def _assert_transcribed(report: dict[str, Any]) -> None:
    md, doc = to_markdown(report), to_html(report)
    lin_events = (report["technical"].get("lineage") or {}).get("events") or []
    model_lin = [(e["relation"], e["inference_state"]) for e in lin_events]
    model_fn = [(f["decision"], f["inference_state"]) for f in report["technical"]["functions"]]
    if model_lin:
        md_lin = [(r[1], r[2]) for r in _md_table(md, "| Function | Relation | Inference |")]
        assert md_lin == model_lin
        assert _html_rows(doc, "lineage") == [i for _, i in model_lin]
        for row, e in zip(_md_table(md, "| Function | Relation | Inference |"), lin_events, strict=True):
            assert row[3] == e["status_text"]  # the statement itself, not a rephrasing
    md_fn = [(r[2], r[3]) for r in _md_table(md, "| Left | Right | Decision | Inference |")]
    assert md_fn == model_fn
    assert _html_rows(doc, "function") == [i for _, i in model_fn]
    for (_, rendered), (_, model) in zip(md_lin if model_lin else [], model_lin, strict=True):
        assert voc.INFERENCE_RANK[rendered] <= voc.INFERENCE_RANK[model]
    # The JSON rendering is the model itself.
    assert json.loads(to_json(report)) == json.loads(json.dumps(report))


NAMES = st.one_of(st.none(), st.text(alphabet="ab|<>&*_`#\\ é", min_size=1, max_size=12))
RELATIONS = sorted(voc.RELATION_INFERENCE)


@st.composite
def lineage_event(draw: Any) -> dict[str, Any]:
    relation = draw(st.sampled_from(RELATIONS))
    ev: dict[str, Any] = {}
    if relation in ("CONTINUATION", "MODIFIED"):
        ev["decision"] = draw(st.sampled_from(sorted(voc.DECISION_INFERENCE)))
    if relation.startswith("RESURRECTED"):
        ev.update(
            code=draw(st.sampled_from(["exact", "similar", None])),
            supporting_families=draw(st.lists(st.sampled_from(["context", "data", "name", "rollback"]), unique=True)),
            reasons=draw(st.lists(st.text(alphabet="ab |<", max_size=8), max_size=2)),
            rule="resurrect@2",
        )
    view = voc.lineage_event_view(relation, ev)
    return {
        "lineage_id": "L",
        "historical_lineage_id": None,
        "relation": relation,
        "instance": {"name": draw(NAMES), "address": draw(st.integers(0, 2**40))},
        **view,
        "decision": ev.get("decision"),
        "provenance": {"lineage_run_id": "R", "lineage_rules": "lineage@2"},
    }


@st.composite
def function_row(draw: Any) -> dict[str, Any]:
    decision = draw(st.sampled_from(sorted(voc.DECISION_INFERENCE)))
    return {
        "left_name": draw(NAMES),
        "right_name": draw(NAMES),
        "left_address": draw(st.one_of(st.none(), st.integers(0, 2**40))),
        "right_address": draw(st.one_of(st.none(), st.integers(0, 2**40))),
        "decision": decision,
        "inference_state": voc.DECISION_INFERENCE[decision],
        "strength_class": "LOW",
        "evidence_diversity": 0,
        "engine_count": 0,
        "probability": None,
        "confidence": {"display": "class", "calibration_state": draw(st.sampled_from(sorted(voc.CALIBRATION_TEXT)))},
        "supporting_families": [],
    }


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    events=st.lists(lineage_event(), max_size=12),
    functions=st.lists(function_row(), max_size=12),
    status=st.sampled_from(["COMPLETED", "COMPLETED_PARTIAL"]),
)
def test_no_renderer_strengthens_any_claim(events, functions, status):
    missing = [{"processor": "ghidriff.diff@1", "outcome": "SKIPPED_UNSUPPORTED", "reason": "x"}] * (
        status == "COMPLETED_PARTIAL"
    )
    report = {
        "scope": {"type": "compare", "id": "run"},
        "generated_at": "t",
        "acet_version": "0",
        "executive": {"headline": [], "uncertainty": [], "completeness": voc.completeness(status, missing)},
        "technical": {
            "runs": [
                {"run_id": "r", "status": status, "profile": {"name": "P", "version": 1}, "resolved_config_hash": "h"}
            ],
            "changes": [],
            "functions": functions,
            "lineage": {"run_id": "R", "status": "COMPLETED", "rules": "lineage@2", "summary": {}, "events": events},
            "missing_evidence": missing,
            "external_events": [],
            "calibration": [],
        },
        "provenance": {},
    }
    assert voc.invariant_problems(report) == []
    _assert_transcribed(report)
    md, doc = to_markdown(report), to_html(report)
    assert ("PARTIAL RESULT" in md) == ("PARTIAL RESULT" in doc) == (status == "COMPLETED_PARTIAL")
    # No hypothesis is ever rendered with a confirmed wording.
    for e in events:
        if e["inference_state"] == "HYPOTHESIS":
            assert "hypothesis" in e["status_text"].lower()


def test_invariants_reject_an_overstating_model(report):
    bad = json.loads(json.dumps(report))
    cand = next(e for e in bad["technical"]["lineage"]["events"] if e["relation"] == "RESURRECTED_CANDIDATE")
    cand["inference_state"] = "CONFIRMED_BY_RULE"
    bad["executive"]["headline"].append("2 resurrection candidates found.")
    bad["executive"]["completeness"]["is_partial"] = False
    problems = voc.invariant_problems(bad)
    assert any("RESURRECTED_CANDIDATE shown as CONFIRMED_BY_RULE" in p for p in problems)
    assert any("without calling them hypotheses" in p for p in problems)
    assert any("partial run is not flagged" in p for p in problems)
