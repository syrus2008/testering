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

# Criteria whose tests cover only part of the wording (none at the moment).
PARTIAL: dict[str, str] = {}
MANUAL = ROOT / "docs" / "traceability" / "manual-protocols.json"
LINKS = ROOT / "docs" / "traceability" / "requirement-links.json"
REQ_OUT = ROOT / "docs" / "traceability" / "requirement-matrix.json"


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
    manual = json.loads(MANUAL.read_text(encoding="utf-8")) if MANUAL.is_file() else {}
    unknown = sorted(set(tests) - {c["id"] for c in parse_spec()})
    if unknown:
        raise SystemExit(f"tests reference unknown acceptance ids: {unknown}")
    rows = []
    for c in parse_spec():
        t = sorted(set(tests.get(c["id"], [])))
        status = "not_started" if not t else ("partial" if c["id"] in PARTIAL else "automated")
        if not t and c["id"] in manual:
            status = "manual_protocol"
        row: dict[str, object] = {**c, "status": status, "tests": t}
        if c["id"] in manual:
            row["manual_protocol"] = manual[c["id"]]
        if t and c["id"] in PARTIAL:
            row["gap"] = PARTIAL[c["id"]]
        rows.append(row)
    summary: dict[str, int] = {}
    for r in rows:
        summary[str(r["status"])] = summary.get(str(r["status"]), 0) + 1
    return {"spec_version": "3.0", "summary": dict(sorted(summary.items())), "criteria": rows}


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def requirement_ids() -> list[str]:
    text = SPEC.read_text(encoding="utf-8")
    return sorted(set(re.findall(r"^(ACET-[A-Z]+-\d{3}) — ", text, re.MULTILINE)))


def build_requirements() -> dict[str, object]:
    """ACET-TRACE-001: requirement → implementation → tests/acceptance, or a versioned waiver."""
    links = json.loads(LINKS.read_text(encoding="utf-8"))
    acc = {c["id"]: c for c in build()["criteria"]}  # type: ignore[index, union-attr]
    rows = []
    for rid in requirement_ids():
        link = links.get(rid)
        if link is None:
            rows.append({"id": rid, "status": "unmapped"})
            continue
        impl_ok = all((ROOT / p).exists() for p in link["implemented_by"])
        acc_ok = [a for a in link["acceptance"] if acc.get(a, {}).get("status") in ("automated", "manual_protocol")]
        test_ok = []
        for t in link["tests"]:
            path, _, fn = t.partition("::")
            if (ROOT / path).is_file() and f"def {fn}(" in (ROOT / path).read_text(encoding="utf-8"):
                test_ok.append(t)
        if impl_ok and (acc_ok or test_ok):
            status = "covered"
        elif impl_ok and link.get("waiver"):
            status = "waived"
        else:
            status = "incomplete"
        rows.append(
            {
                "id": rid,
                "status": status,
                "implemented_by": link["implemented_by"],
                "acceptance": acc_ok,
                "tests": test_ok,
                **({"waiver": link["waiver"]} if link.get("waiver") else {}),
            }
        )
    summary: dict[str, int] = {}
    for r in rows:
        summary[str(r["status"])] = summary.get(str(r["status"]), 0) + 1
    return {"spec_version": "3.0", "summary": dict(sorted(summary.items())), "requirements": rows}


def render_requirements() -> str:
    return json.dumps(build_requirements(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    text, req = render(), render_requirements()
    if "--check" in sys.argv:
        stale = [
            p.name for p, t in ((OUT, text), (REQ_OUT, req)) if not p.is_file() or p.read_text(encoding="utf-8") != t
        ]
        if stale:
            print(f"stale: {stale}: run python tools/gen_traceability.py", file=sys.stderr)
            raise SystemExit(1)
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        REQ_OUT.write_text(req, encoding="utf-8")
        print(json.dumps(build()["summary"]), json.dumps(build_requirements()["summary"]))
