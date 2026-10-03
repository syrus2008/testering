"""Renderers: JSON (canonical), Markdown, self-contained HTML, CSV (spec §42, ACC-021).

HTML is fully offline (no external resources) and escapes every value.
Writes are atomic (temp + rename).
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
from pathlib import Path
from typing import Any

from acet.domain.error_codes import AcetError


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _cell(v: Any) -> str:
    """Markdown table cell: pipes and newlines cannot break the table."""
    return str("—" if v is None or v == "" else v).replace("|", "\\|").replace("\n", " ")


def _fn_label(name: str | None, addr: int | None) -> str:
    return name or (hex(addr) if addr is not None else "—")


def _lineage(report: dict[str, Any]) -> dict[str, Any]:
    return report["technical"].get("lineage") or {"status": "NOT_COMPUTED", "events": [], "summary": {}}


def to_markdown(report: dict[str, Any]) -> str:
    ex, te = report["executive"], report["technical"]
    comp = ex["completeness"]
    out = [
        f"# ACET report — {report['scope']['type']} `{report['scope']['id']}`",
        "",
        f"_Generated {report['generated_at']} by ACET {report['acet_version']}. No global score is computed._",
        "",
    ]
    if comp["is_partial"]:
        out += [f"> **⚠ {comp['title']}**", ">", f"> Run status: **{comp['run_status']}**."]
        out += [f"> - Missing: {m['processor']} — {m.get('outcome')}: {m.get('reason')}" for m in comp["missing"]]
        out += [">", f"> **{comp['statement']}**", ""]
    out += ["## Executive summary", ""] + [f"- {h}" for h in ex["headline"]]
    out += ["", "### Uncertainty", ""] + [f"- {u}" for u in ex["uncertainty"]]
    out += [
        "",
        "## Changes by dimension",
        "",
        "| Component | Dimension | State | Severity | Reliability |",
        "|---|---|---|---|---|",
    ]
    out += [
        f"| {_cell(c['component_role'])} | {c['dimension']} | {c['measurement']['state']} | {c['severity_class']} | "
        f"{c['reliability_class']} |"
        for c in te["changes"]
    ]
    lin = _lineage(report)
    out += ["", "## Lineage", ""]
    if lin["status"] == "NOT_COMPUTED":
        out.append(f"_{lin.get('note') or 'Lineage not computed for this transition.'}_")
    else:
        out.append(f"Lineage run `{lin['run_id']}` ({lin['status']}, rules {lin.get('rules')}).")
        confirmed = [e for e in lin["events"] if e["relation"] == "RESURRECTED_CONFIRMED"]
        hyps = [e for e in lin["events"] if e["inference_state"] == "HYPOTHESIS"]
        if confirmed:
            out += ["", "### Resurrections confirmed by rule", ""]
            out += [
                f"- {_fn_label(e['instance']['name'], e['instance']['address'])} — {e['status_text']}. "
                f"{e['explanation']} (rule {e['rule']})"
                for e in confirmed
            ]
        if hyps:
            out += ["", "### Hypotheses (not established)", ""]
            out += [
                f"- {_fn_label(e['instance']['name'], e['instance']['address'])} — **{e['status_text']}**"
                + (f". {e['explanation']}" if e["explanation"] else "")
                for e in hyps
            ]
        rejected = [e for e in lin["events"] if e["inference_state"] == "UNRESOLVED" and e["explanation"]]
        if rejected:
            out += ["", "### Hypotheses considered and rejected", ""]
            out += [
                f"- {_fn_label(e['instance']['name'], e['instance']['address'])} — {e['status_text']}. "
                f"{e['explanation']}"
                for e in rejected
            ]
        out += [
            "",
            "| Function | Relation | Inference | Statement | Rule | Supporting | Contradicting | Historical lineage |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for e in lin["events"]:
            out.append(
                f"| {_cell(_fn_label(e['instance']['name'], e['instance']['address']))} | {e['relation']} | "
                f"{e['inference_state']} | {_cell(e['status_text'])} | {_cell(e['rule'])} | "
                f"{_cell(', '.join(e['supporting_families']))} | {_cell(', '.join(e['contradicting_families']))} | "
                f"{_cell((e['historical_lineage_id'] or '')[:13])} |"
            )
    out += [
        "",
        "## Functions",
        "",
        "| Left | Right | Decision | Inference | Strength | Diversity | Engines | Calibration |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in te["functions"]:
        out.append(
            f"| {_cell(_fn_label(f['left_name'], f['left_address']))} | "
            f"{_cell(_fn_label(f['right_name'], f['right_address']))} | {f['decision']} | {f['inference_state']} | "
            f"{f['strength_class']} | {f['evidence_diversity']} | {f['engine_count']} | "
            f"{f['confidence']['calibration_state']} |"
        )
    if te.get("calibration"):
        out += ["", "## Confidence calibration", ""] + [f"- {c['engine']}: {c['text']}" for c in te["calibration"]]
    out += ["", "## Provenance", ""]
    for r in te["runs"]:
        out.append(
            f"- run `{r['run_id']}` {r['status']} profile {r['profile']['name']}@{r['profile']['version']}, "
            f"config `{r['resolved_config_hash'][:16]}`"
        )
    if te["missing_evidence"]:
        out += ["", "## Missing evidence", "", f"_{comp['statement']}_", ""] + [
            f"- {m['processor']}: {m['outcome']} — {m['reason']}" for m in te["missing_evidence"]
        ]
    if te.get("external_events"):
        out += ["", "## External events (temporal correlation only)", ""] + [
            f"- {e['occurred_at']} {e['event_type']}: {e['summary']} ({e['source_class']}) — {e['interpretation']}"
            for e in te["external_events"]
        ]
    return "\n".join(out) + "\n"


_CSS = (
    "body{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px;color:#1b1b1b;background:#fff}"
    "table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccc;padding:4px 8px;"
    "text-align:left;font-size:.9rem}th{background:#f2f2f2}.cls{font-weight:600}"
    ".partial{border:3px solid #b45309;background:#fff7ed;color:#7c2d12;padding:1rem;margin:1rem 0}"
    ".partial strong{font-size:1.1rem}.hyp{font-style:italic;color:#7c2d12}"
    "@media (prefers-color-scheme: dark){body{background:#151515;color:#e8e8e8}th{background:#262626}"
    "th,td{border-color:#444}.partial{background:#2a1606;color:#fed7aa;border-color:#f59e0b}.hyp{color:#fdba74}}"
)


def to_html(report: dict[str, Any]) -> str:
    e = html.escape
    ex, te = report["executive"], report["technical"]
    comp = ex["completeness"]
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width'>"
        f"<title>ACET report</title><style>{_CSS}</style></head><body>",
        f"<h1>ACET report — {e(report['scope']['type'])}</h1><p><small>{e(report['generated_at'])} · ACET "
        f"{e(report['acet_version'])} · no global score</small></p>",
    ]
    if comp["is_partial"]:
        parts.append(
            f"<div class=partial role=alert><strong>⚠ {e(comp['title'])}</strong>"
            f"<p>Run status: <b>{e(comp['run_status'])}</b>.</p><ul>"
            + "".join(
                f"<li>Missing: {e(str(m['processor']))} — {e(str(m.get('outcome')))}: {e(str(m.get('reason')))}</li>"
                for m in comp["missing"]
            )
            + f"</ul><p><b>{e(comp['statement'])}</b></p></div>"
        )
    parts.append("<h2>Executive summary</h2><ul>" + "".join(f"<li>{e(h)}</li>" for h in ex["headline"]) + "</ul>")
    parts.append("<h3>Uncertainty</h3><ul>" + "".join(f"<li>{e(u)}</li>" for u in ex["uncertainty"]) + "</ul>")
    parts.append(
        "<h2>Changes by dimension</h2><table><thead><tr><th>Component</th><th>Dimension</th><th>State</th>"
        "<th>Severity</th><th>Reliability</th></tr></thead><tbody>"
        + "".join(
            f"<tr><td>{e(str(c['component_role']))}</td><td>{e(c['dimension'])}</td>"
            f"<td>{e(c['measurement']['state'])}</td><td class=cls>{e(c['severity_class'])}</td>"
            f"<td>{e(c['reliability_class'])}</td></tr>"
            for c in te["changes"]
        )
        + "</tbody></table>"
    )
    lin = _lineage(report)
    parts.append("<h2>Lineage</h2>")
    if lin["status"] == "NOT_COMPUTED":
        parts.append(f"<p><i>{e(lin.get('note') or 'Lineage not computed for this transition.')}</i></p>")
    else:
        parts.append(f"<p>Lineage run <code>{e(str(lin['run_id']))}</code> ({e(lin['status'])}).</p>")
        confirmed = [x for x in lin["events"] if x["relation"] == "RESURRECTED_CONFIRMED"]
        hyps = [x for x in lin["events"] if x["inference_state"] == "HYPOTHESIS"]
        if confirmed:
            parts.append(
                "<h3>Resurrections confirmed by rule</h3><ul>"
                + "".join(
                    f"<li data-inference={e(x['inference_state'])}>"
                    f"{e(_fn_label(x['instance']['name'], x['instance']['address']))} — {e(x['status_text'])}. "
                    f"{e(x['explanation'] or '')} (rule {e(x['rule'])})</li>"
                    for x in confirmed
                )
                + "</ul>"
            )
        if hyps:
            parts.append(
                "<h3>Hypotheses (not established)</h3><ul>"
                + "".join(
                    f"<li class=hyp data-inference={e(x['inference_state'])}>"
                    f"{e(_fn_label(x['instance']['name'], x['instance']['address']))} — <b>{e(x['status_text'])}</b>"
                    + (f". {e(x['explanation'])}" if x["explanation"] else "")
                    + "</li>"
                    for x in hyps
                )
                + "</ul>"
            )
        rejected = [x for x in lin["events"] if x["inference_state"] == "UNRESOLVED" and x["explanation"]]
        if rejected:
            parts.append(
                "<h3>Hypotheses considered and rejected</h3><ul>"
                + "".join(
                    f"<li data-inference={e(x['inference_state'])}>"
                    f"{e(_fn_label(x['instance']['name'], x['instance']['address']))} — {e(x['status_text'])}. "
                    f"{e(x['explanation'])}</li>"
                    for x in rejected
                )
                + "</ul>"
            )
        parts.append(
            "<table><thead><tr><th>Function</th><th>Relation</th><th>Inference</th><th>Statement</th><th>Rule</th>"
            "<th>Supporting</th><th>Contradicting</th><th>Historical lineage</th></tr></thead><tbody>"
            + "".join(
                f"<tr data-kind=lineage data-relation={e(x['relation'])} data-inference={e(x['inference_state'])}>"
                f"<td>{e(_fn_label(x['instance']['name'], x['instance']['address']))}</td><td>{e(x['relation'])}</td>"
                f"<td class=cls>{e(x['inference_state'])}</td><td>{e(x['status_text'])}</td><td>{e(x['rule'])}</td>"
                f"<td>{e(', '.join(x['supporting_families']))}</td><td>{e(', '.join(x['contradicting_families']))}</td>"
                f"<td>{e((x['historical_lineage_id'] or '')[:13])}</td></tr>"
                for x in lin["events"]
            )
            + "</tbody></table>"
        )
    parts.append(
        "<h2>Functions</h2><table><thead><tr><th>Left</th><th>Right</th><th>Decision</th><th>Inference</th>"
        "<th>Strength</th><th>Diversity</th><th>Engines</th><th>Supporting families</th><th>Calibration</th>"
        "</tr></thead><tbody>"
        + "".join(
            f"<tr data-kind=function data-inference={e(f['inference_state'])}>"
            f"<td>{e(_fn_label(f['left_name'], f['left_address']))}</td>"
            f"<td>{e(_fn_label(f['right_name'], f['right_address']))}</td><td class=cls>{e(f['decision'])}</td>"
            f"<td>{e(f['inference_state'])}</td><td>{e(f['strength_class'])}</td><td>{f['evidence_diversity']}</td>"
            f"<td>{f['engine_count']}</td><td>{e(', '.join(f['supporting_families']))}</td>"
            f"<td>{e(f['confidence']['calibration_state'])}</td></tr>"
            for f in te["functions"]
        )
        + "</tbody></table>"
    )
    if te.get("calibration"):
        parts.append(
            "<h2>Confidence calibration</h2><ul>"
            + "".join(f"<li>{e(c['engine'])}: {e(c['text'])}</li>" for c in te["calibration"])
            + "</ul>"
        )
    if te["missing_evidence"]:
        parts.append(
            f"<h2>Missing evidence</h2><p><i>{e(comp['statement'])}</i></p><ul>"
            + "".join(
                f"<li>{e(str(m['processor']))}: {e(str(m['outcome']))} — {e(str(m['reason']))}</li>"
                for m in te["missing_evidence"]
            )
            + "</ul>"
        )
    if te.get("external_events"):
        parts.append(
            "<h2>External events (temporal correlation only)</h2><ul>"
            + "".join(
                f"<li>{e(str(x['occurred_at']))} {e(str(x['event_type']))}: {e(str(x['summary']))} "
                f"({e(str(x['source_class']))}) — {e(x['interpretation'])}</li>"
                for x in te["external_events"]
            )
            + "</ul>"
        )
    parts.append("<h2>Provenance</h2><pre>" + e(json.dumps(report["provenance"], indent=2)) + "</pre></body></html>\n")
    return "".join(parts)


def to_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    cols = [
        "left_artifact",
        "left_address",
        "left_name",
        "right_artifact",
        "right_address",
        "right_name",
        "decision",
        "inference_state",
        "calibration_state",
        "strength_class",
        "evidence_diversity",
        "engine_count",
        "contradicting",
        "side",
    ]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for f in report["technical"]["functions"]:
        w.writerow({**f, "calibration_state": f["confidence"]["calibration_state"]})
    return buf.getvalue()


RENDERERS = {"json": to_json, "md": to_markdown, "html": to_html, "csv": to_csv}


def write_report(report: dict[str, Any], fmt: str, dest: Path) -> Path:
    if fmt not in RENDERERS:
        raise AcetError("ACET-REP-001", f"unknown format {fmt}")
    try:
        text = RENDERERS[fmt](report)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, dest)
    except OSError as exc:
        raise AcetError("ACET-REP-001", f"{type(exc).__name__}") from exc
    return dest
