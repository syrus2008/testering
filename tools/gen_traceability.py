"""Generate docs/traceability/acceptance-matrix.json (ACET-TRACE-002).

Sources:
* the acceptance criteria ACC-001..150 parsed from the specification text;
* ``@pytest.mark.acceptance("ACC-xxx", ...)`` markers found in tests/ (AST scan).

Usage: python tools/gen_traceability.py [--check]
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "spec" / "ACET_Master_Specification_v3_FINAL.txt"
OUT = ROOT / "docs" / "traceability" / "acceptance-matrix.json"

# Criteria whose tests cover only part of the wording, until later roadmap phases.
PARTIAL = {
    "ACC-004": "static guarantee only (no execution primitives on import paths); runtime proof needs P3 workers",
    "ACC-017": "domain completeness only; report/UI rendering arrives with P9/P11/P13",
    "ACC-035": "import, product creation and soft delete audited; analysis/annotation audit with P4+",
    "ACC-037": "reconcile covers dangling refs and orphans; Doctor UI with P13",
    "ACC-042": "import via CLI only; analyze/compare/export arrive with P4-P11",
    "ACC-043": "codes 0/10/20/40 exercised; 30 (analysis failure) needs P4+",
    "ACC-045": "hot metadata backup proven; settings/annotations restore flow with P11",
    "ACC-102": "error mapping proven; processor runs arrive with P3",
}


def parse_spec() -> list[dict[str, str]]:
    lines = [ln.strip() for ln in SPEC.read_text(encoding="utf-8").splitlines()]
    out: list[dict[str, str]] = []
    for i, ln in enumerate(lines):
        if re.fullmatch(r"ACC-\d{3}", ln) and i + 2 < len(lines):
            out.append({"id": ln, "subject": lines[i + 1], "criterion": lines[i + 2]})
    ids = [c["id"] for c in out]
    assert ids == [f"ACC-{n:03d}" for n in range(1, 151)], "spec ACC list incomplete"
    return out


def scan_tests() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for py in sorted((ROOT / "tests").rglob("test_*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        rel = py.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "acceptance":
                    for arg in dec.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            found.setdefault(arg.value, []).append(f"{rel}::{node.name}")
    return found


def build() -> dict[str, object]:
    tests = scan_tests()
    unknown = sorted(set(tests) - {c["id"] for c in parse_spec()})
    if unknown:
        raise SystemExit(f"tests reference unknown acceptance ids: {unknown}")
    rows = []
    for c in parse_spec():
        t = sorted(set(tests.get(c["id"], [])))
        status = "not_started" if not t else ("partial" if c["id"] in PARTIAL else "automated")
        row: dict[str, object] = {**c, "status": status, "tests": t}
        if t and c["id"] in PARTIAL:
            row["gap"] = PARTIAL[c["id"]]
        rows.append(row)
    summary: dict[str, int] = {}
    for r in rows:
        summary[str(r["status"])] = summary.get(str(r["status"]), 0) + 1
    return {"spec_version": "3.0", "summary": dict(sorted(summary.items())), "criteria": rows}


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    text = render()
    if "--check" in sys.argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print("acceptance-matrix.json is stale: run python tools/gen_traceability.py", file=sys.stderr)
            raise SystemExit(1)
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        print(json.dumps(build()["summary"]))
