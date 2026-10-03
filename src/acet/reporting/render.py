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


def to_markdown(report: dict[str, Any]) -> str:
    ex, te = report["executive"], report["technical"]
    out = [
        f"# ACET report — {report['scope']['type']} `{report['scope']['id']}`",
        "",
        f"_Generated {report['generated_at']} by ACET {report['acet_version']}. No global score is computed._",
        "",
        "## Executive summary",
        "",
    ]
    out += [f"- {h}" for h in ex["headline"]]
    out += ["", "### Uncertainty", ""] + [f"- {u}" for u in ex["uncertainty"]]
    out += [
        "",
        "## Changes by dimension",
        "",
        "| Component | Dimension | State | Severity | Reliability |",
        "|---|---|---|---|---|",
    ]
    out += [
        f"| {c['component_role']} | {c['dimension']} | {c['measurement']['state']} | {c['severity_class']} | "
        f"{c['reliability_class']} |"
        for c in te["changes"]
    ]
    out += [
        "",
        "## Functions",
        "",
        "| Left | Right | Decision | Strength | Diversity | Engines |",
        "|---|---|---|---|---|---|",
    ]
    for f in te["functions"]:
        left = f["left_name"] or (hex(f["left_address"]) if f["left_address"] is not None else "—")
        right = f["right_name"] or (hex(f["right_address"]) if f["right_address"] is not None else "—")
        out.append(
            f"| {left} | {right} | {f['decision']} | {f['strength_class']} | {f['evidence_diversity']} | "
            f"{f['engine_count']} |"
        )
    out += ["", "## Provenance", ""]
    for r in te["runs"]:
        out.append(
            f"- run `{r['run_id']}` {r['status']} profile {r['profile']['name']}@{r['profile']['version']}, "
            f"config `{r['resolved_config_hash'][:16]}`"
        )
    if te["missing_evidence"]:
        out += ["", "## Missing evidence", ""] + [
            f"- {m['processor']}: {m['outcome']} — {m['reason']}" for m in te["missing_evidence"]
        ]
    if te.get("external_events"):
        out += ["", "## External events (temporal correlation only)", ""] + [
            f"- {e['occurred_at']} {e['event_type']}: {e['summary']} ({e['source_class']})"
            for e in te["external_events"]
        ]
    return "\n".join(out) + "\n"


_CSS = (
    "body{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px;color:#1b1b1b;background:#fff}"
    "table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccc;padding:4px 8px;"
    "text-align:left;font-size:.9rem}th{background:#f2f2f2}.cls{font-weight:600}"
    "@media (prefers-color-scheme: dark){body{background:#151515;color:#e8e8e8}th{background:#262626}"
    "th,td{border-color:#444}}"
)


def to_html(report: dict[str, Any]) -> str:
    e = html.escape
    md_rows = []
    for c in report["technical"]["changes"]:
        md_rows.append(
            f"<tr><td>{e(str(c['component_role']))}</td><td>{e(c['dimension'])}</td>"
            f"<td>{e(c['measurement']['state'])}</td><td class=cls>{e(c['severity_class'])}</td>"
            f"<td>{e(c['reliability_class'])}</td></tr>"
        )
    fn_rows = []
    for f in report["technical"]["functions"]:
        left = f["left_name"] or (hex(f["left_address"]) if f["left_address"] is not None else "—")
        right = f["right_name"] or (hex(f["right_address"]) if f["right_address"] is not None else "—")
        fn_rows.append(
            f"<tr><td>{e(str(left))}</td><td>{e(str(right))}</td><td class=cls>{e(f['decision'])}</td>"
            f"<td>{e(f['strength_class'])}</td><td>{f['evidence_diversity']}</td><td>{f['engine_count']}</td>"
            f"<td>{e(', '.join(f['supporting_families']))}</td></tr>"
        )
    ex = report["executive"]
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width'>"
        f"<title>ACET report</title><style>{_CSS}</style></head><body>"
        f"<h1>ACET report — {e(report['scope']['type'])}</h1><p><small>{e(report['generated_at'])} · ACET "
        f"{e(report['acet_version'])} · no global score</small></p><h2>Executive summary</h2><ul>"
        + "".join(f"<li>{e(h)}</li>" for h in ex["headline"])
        + "</ul><h3>Uncertainty</h3><ul>"
        + "".join(f"<li>{e(u)}</li>" for u in ex["uncertainty"])
        + "</ul>"
        "<h2>Changes by dimension</h2><table><thead><tr><th>Component</th><th>Dimension</th><th>State</th>"
        "<th>Severity</th><th>Reliability</th></tr></thead><tbody>" + "".join(md_rows) + "</tbody></table>"
        "<h2>Functions</h2><table><thead><tr><th>Left</th><th>Right</th><th>Decision</th><th>Strength</th>"
        "<th>Diversity</th><th>Engines</th><th>Supporting families</th></tr></thead><tbody>"
        + "".join(fn_rows)
        + "</tbody></table><h2>Provenance</h2><pre>"
        + e(json.dumps(report["provenance"], indent=2))
        + "</pre>"
        "</body></html>\n"
    )


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
        "strength_class",
        "evidence_diversity",
        "engine_count",
        "contradicting",
        "side",
    ]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for f in report["technical"]["functions"]:
        w.writerow(f)
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
