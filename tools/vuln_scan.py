"""Offline SBOM vulnerability scan + triage record (spec §112, ACET-VULN-001, ACC-126).

Usage: python tools/vuln_scan.py <sbom.json> <advisories.json> <out security-scan-summary.json> [--triage triage.json]

triage.json: {"<advisory id>": {"decision": "not-affected|mitigated|accepted|fixed", "rationale": "..."}}

advisories.json: OSV-style export [{"id", "package", "affected_versions": [..], "severity", "summary"}]
(downloaded by the release pipeline; the scan itself runs offline). Every finding needs a triage
decision (exploitability in ACET's context) before a STABLE release; untriaged findings mark the
summary FAILED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

TRIAGE_DECISIONS = {"not-affected", "mitigated", "accepted", "fixed"}


def _valid_triage(t: dict[str, object] | None) -> bool:
    if not t:
        return False
    return t.get("decision") in TRIAGE_DECISIONS and bool(str(t.get("rationale") or "").strip())


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
    untriaged = [f for f in findings if not _valid_triage(f["triage"])]
    return {
        "status": "FAILED" if untriaged else "PASSED",
        "scanned_at": datetime.now(UTC).isoformat(),
        "components": len(comps),
        "advisories": len(advisories),
        "findings": findings,
        "untriaged": [f["id"] for f in untriaged],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline SBOM vulnerability scan with triage (ACET-VULN-001).")
    ap.add_argument("sbom", type=Path)
    ap.add_argument("advisories", type=Path, help="OSV-style advisory export (list)")
    ap.add_argument("out", type=Path)
    ap.add_argument("--triage", type=Path)
    args = ap.parse_args(argv)
    sb = json.loads(args.sbom.read_text(encoding="utf-8"))
    adv = json.loads(args.advisories.read_text(encoding="utf-8"))
    if not isinstance(adv, list):
        ap.error("advisories must be a JSON list")
    tri = json.loads(args.triage.read_text(encoding="utf-8")) if args.triage else {}
    res = scan(sb, adv, tri)
    # Bind the summary to the exact inputs so the release gate can check provenance.
    res["sbom_sha256"] = hashlib.sha256(args.sbom.read_bytes()).hexdigest()
    res["advisories_sha256"] = hashlib.sha256(args.advisories.read_bytes()).hexdigest()
    args.out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(res["status"])
    return 0 if res["status"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
