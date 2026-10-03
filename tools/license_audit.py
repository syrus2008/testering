"""License audit: validate ``docs/license-audit.json`` and render ``docs/license-audit.md`` (ACET-LIC-001).

The JSON file is the source of truth; the Markdown file is generated from it so the two
cannot drift. The release gate uses :func:`problems` — an audit is *closed* only when every
component row is CLOSED with concrete obligations, and the approval block names a person
and a date.

Usage:
  python tools/license_audit.py render            # rewrite docs/license-audit.md
  python tools/license_audit.py check [--audit F] # exit 1 and list open items
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUDIT_JSON = ROOT / "docs" / "license-audit.json"
AUDIT_MD = ROOT / "docs" / "license-audit.md"

ROW_FIELDS = ("component", "version", "spdx", "distribution", "redistribution", "obligations", "how_satisfied")
# Wording that means a decision was not taken. Matched case-insensitively in every text field.
OPEN_MARKERS = re.compile(
    r"\b(to audit|to review|to decide|to be decided|choose|tbd|todo|incomplete|pending|unknown|n/?a yet)\b",
    re.IGNORECASE,
)
SPDX = re.compile(r"^[A-Za-z0-9.+\-]+( (WITH|OR|AND) [A-Za-z0-9.+\-]+)*$")


def load(path: Path = AUDIT_JSON) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def problems(audit: dict[str, Any]) -> list[str]:
    out: list[str] = []
    comps = audit.get("components")
    if not isinstance(comps, list) or not comps:
        return ["license audit: no components"]
    for i, c in enumerate(comps):
        name = c.get("component") or f"#{i}"
        for f in ROW_FIELDS:
            v = c.get(f)
            if v in (None, "", "—", []):
                out.append(f"license audit: {name}: missing {f}")
        if c.get("status") != "CLOSED":
            out.append(f"license audit: {name}: status {c.get('status')!r} (must be CLOSED)")
        spdx = str(c.get("spdx") or "")
        if spdx and not (SPDX.match(spdx) or spdx.startswith("LicenseRef-")):
            out.append(f"license audit: {name}: not an SPDX expression: {spdx!r}")
        texts = [str(c.get(f) or "") for f in ROW_FIELDS if f != "obligations"] + list(c.get("obligations") or [])
        for t in texts:
            m = OPEN_MARKERS.search(t)
            if m:
                out.append(f"license audit: {name}: undecided wording {m.group(0)!r}")
                break
    appr = audit.get("approval") or {}
    if appr.get("status") != "APPROVED":
        out.append(f"license audit: approval status {appr.get('status')!r} (must be APPROVED)")
    if not str(appr.get("approved_by") or "").strip():
        out.append("license audit: approval has no named approver")
    try:
        datetime.fromisoformat(str(appr.get("approved_at")))
    except ValueError:
        out.append("license audit: approval has no valid approved_at date")
    return out


def render(audit: dict[str, Any]) -> str:
    appr = audit.get("approval") or {}
    lines = [
        "# License audit (spec §45, §113, ACET-LIC-001)",
        "",
        "<!-- Generated from docs/license-audit.json by tools/license_audit.py — do not edit by hand. -->",
        "",
        f"Scope: {audit.get('scope', '')}",
        "",
        f"**Approval:** {appr.get('status')} — approver: {appr.get('approved_by') or '(none)'}"
        f" — date: {appr.get('approved_at') or '(none)'}",
        "",
        str(appr.get("note") or ""),
        "",
        "| Component | Version | SPDX | Distribution | Redistribution | Status |",
        "|---|---|---|---|---|---|",
    ]
    for c in audit.get("components", []):
        lines.append(
            f"| {c['component']} | {c['version']} | {c['spdx']} | {c['distribution']} | {c['redistribution']} |"
            f" {c['status']} |"
        )
    lines.append("")
    for c in audit.get("components", []):
        lines += [f"## {c['component']}", "", "Obligations:"]
        lines += [f"- {o}" for o in c.get("obligations", [])]
        lines += ["", f"How satisfied: {c.get('how_satisfied', '')}", ""]
    open_items = problems(audit)
    lines += ["## Open items", ""]
    lines += [f"- {p}" for p in open_items] or ["- none"]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("render", help="rewrite docs/license-audit.md from the JSON audit")
    c = sub.add_parser("check", help="list open items; exit 1 if the audit is not closed")
    c.add_argument("--audit", type=Path, default=AUDIT_JSON)
    c.add_argument("--rendered", action="store_true", help="also fail if license-audit.md is stale")
    args = ap.parse_args(argv)
    if args.cmd == "render":
        AUDIT_MD.write_text(render(load()), encoding="utf-8")
        print(f"wrote {AUDIT_MD.relative_to(ROOT)}")
        return 0
    audit = load(args.audit)
    probs = problems(audit)
    if args.rendered and AUDIT_MD.read_text(encoding="utf-8") != render(audit):
        probs.append("docs/license-audit.md is stale: run tools/license_audit.py render")
    print("\n".join(probs) or "license audit closed")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
