"""Offline SBOM vulnerability scan + triage record (spec §112, ACET-VULN-001, ACC-126).

Usage: python tools/vuln_scan.py <sbom.json> <advisories.json> <out security-scan-summary.json> [--triage triage.json]

advisories.json: OSV-style export [{"id", "package", "affected_versions": [..], "severity", "summary"}]
(downloaded by the release pipeline; the scan itself runs offline). Every finding needs a triage
decision (exploitability in ACET's context) before a STABLE release; untriaged findings mark the
summary FAILED.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path


def scan(sbom: dict, advisories: list[dict], triage: dict[str, dict]) -> dict:
    comps = {(c["name"].lower(), str(c.get("version"))) for c in sbom.get("components", [])}
    findings = []
    for adv in advisories:
        for name, ver in comps:
            if name == adv["package"].lower() and ver in [str(v) for v in adv.get("affected_versions", [])]:
                t = triage.get(adv["id"])
                findings.append(
                    {
                        "id": adv["id"],
                        "package": name,
                        "version": ver,
                        "severity": adv.get("severity"),
                        "summary": adv.get("summary"),
                        "triage": t,
                    }
                )
    untriaged = [f for f in findings if not f["triage"]]
    return {
        "status": "FAILED" if untriaged else "PASSED",
        "scanned_at": datetime.now(UTC).isoformat(),
        "components": len(comps),
        "advisories": len(advisories),
        "findings": findings,
        "untriaged": [f["id"] for f in untriaged],
    }


if __name__ == "__main__":
    sb = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    adv = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    tri = json.loads(Path(sys.argv[sys.argv.index("--triage") + 1]).read_text()) if "--triage" in sys.argv else {}
    res = scan(sb, adv, tri)
    Path(sys.argv[3]).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(res["status"])
    raise SystemExit(0 if res["status"] == "PASSED" else 1)
