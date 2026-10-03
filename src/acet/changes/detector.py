"""Change detection with separated dimensions (spec §23, ACET-CHG-001/002, ACC-016/017/040/071).

There is deliberately no global score: each dimension is reported with its own
MeasurementState, metrics, baseline class and reliability class. A dimension
that was not measured is UNKNOWN / NOT_MEASURED, never 0. Extraction quality is
a reliability dimension, not a software change (ACET-SCI-003).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from acet.analysis.results import derived_for_artifact
from acet.application.workspace import Workspace
from acet.changes.baseline import BaselineClass, classify
from acet.changes.events import correlated_events
from acet.domain.canonical import stable_json
from acet.domain.enums import ChangeDimension, MeasurementState
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.storage import repositories as repo

RULES = "changes@1"
M = MeasurementState


@dataclass
class DimensionResult:
    dimension: ChangeDimension
    state: MeasurementState
    metrics: dict[str, Any] = field(default_factory=dict)
    baseline: dict[str, Any] = field(default_factory=dict)
    severity_class: str = BaselineClass.UNKNOWN.value
    reliability_class: str = "UNKNOWN"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension.value,
            "state": self.state.value,
            "metrics": self.metrics,
            "baseline": self.baseline,
            "severity_class": self.severity_class,
            "reliability_class": self.reliability_class,
            "notes": self.notes,
        }


def _val(fam: dict[str, Any] | None) -> Any:
    return fam.get("value") if fam and fam.get("state") == "MEASURED" else None


def _binary(
    lpe: dict[str, Any] | None, rpe: dict[str, Any] | None, lh: dict[str, Any] | None, rh: dict[str, Any] | None
) -> DimensionResult:
    d = DimensionResult(ChangeDimension.BINARY, M.MEASURED)
    if lh and rh:
        d.metrics["size_delta_ratio"] = round((rh["size_bytes"] - lh["size_bytes"]) / max(1, lh["size_bytes"]), 6)
    ls, rs = _val((lpe or {}).get("sections")), _val((rpe or {}).get("sections"))
    if ls is not None and rs is not None:
        la, ra = {s["name"]: s for s in ls}, {s["name"]: s for s in rs}
        d.metrics["sections_added"] = sorted(set(ra) - set(la))
        d.metrics["sections_removed"] = sorted(set(la) - set(ra))
        d.metrics["sections_changed"] = sorted(n for n in set(la) & set(ra) if la[n]["sha256"] != ra[n]["sha256"])
    else:
        d.state = M.PARTIAL
    lr, rr = _val((lpe or {}).get("resources")), _val((rpe or {}).get("resources"))
    if lr is not None and rr is not None:
        a = {e["sha256"] for e in lr["entries"]}
        b = {e["sha256"] for e in rr["entries"]}
        d.metrics["resources_changed"] = len(a ^ b)
    tl, tr = (lh or {}).get("tlsh", {}), (rh or {}).get("tlsh", {})
    if tl.get("state") == "MEASURED" and tr.get("state") == "MEASURED":
        try:
            import tlsh

            d.metrics["tlsh_distance"] = tlsh.diff(tl["value"], tr["value"])
        except ImportError:
            d.metrics["tlsh_distance"] = None
    else:
        d.metrics["tlsh_distance"] = None  # NOT_MEASURED ≠ 0 (ACET-CHG-001)
        d.notes.append("TLSH not measured")
    return d


def _build(lpe: dict[str, Any] | None, rpe: dict[str, Any] | None) -> DimensionResult:
    if not lpe or not rpe or lpe.get("format_state") != "MEASURED" or rpe.get("format_state") != "MEASURED":
        return DimensionResult(ChangeDimension.BUILD, M.UNSUPPORTED, notes=["no PE facts"])
    d = DimensionResult(ChangeDimension.BUILD, M.MEASURED)
    lhd, rhd = _val(lpe["headers"]) or {}, _val(rpe["headers"]) or {}
    d.metrics["linker_version_changed"] = lhd.get("linker_version") != rhd.get("linker_version")
    d.metrics["pe_timestamp_changed"] = lhd.get("pe_timestamp") != rhd.get("pe_timestamp")
    d.notes.append("PE timestamp is provenance only; never a build date (ACET-PE-002)")
    lrh, rrh = _val(lpe["rich_header"]) or {}, _val(rpe["rich_header"]) or {}
    d.metrics["toolchain_hint_changed"] = (lrh.get("entries") != rrh.get("entries")) if (lrh or rrh) else None
    la, ra = _val(lpe["authenticode"]) or {}, _val(rpe["authenticode"]) or {}
    d.metrics["signature_presence_changed"] = bool(la.get("present")) != bool(ra.get("present"))
    d.metrics["signer_changed"] = (
        (la.get("signer") != ra.get("signer")) if la.get("present") and ra.get("present") else None
    )
    ld = [e.get("codeview", {}).get("guid") for e in (_val(lpe["debug"]) or {}).get("entries", [])]
    rd = [e.get("codeview", {}).get("guid") for e in (_val(rpe["debug"]) or {}).get("entries", [])]
    d.metrics["pdb_guid_changed"] = (ld != rd) if (any(ld) or any(rd)) else None
    return d


def _semantic(
    lpe: dict[str, Any] | None, rpe: dict[str, Any] | None, lst: dict[str, Any] | None, rst: dict[str, Any] | None
) -> DimensionResult:
    d = DimensionResult(ChangeDimension.SEMANTIC, M.MEASURED)
    li, ri = _val((lpe or {}).get("imports")), _val((rpe or {}).get("imports"))
    if li is not None and ri is not None:
        a = {f"{x['dll'].lower()}!{s}" for x in li["dlls"] for s in x["symbols"]}
        b = {f"{x['dll'].lower()}!{s}" for x in ri["dlls"] for s in x["symbols"]}
        d.metrics["imports_added"] = sorted(b - a)
        d.metrics["imports_removed"] = sorted(a - b)
    else:
        d.state = M.PARTIAL
    le, re_ = _val((lpe or {}).get("exports")), _val((rpe or {}).get("exports"))
    if le is not None and re_ is not None:
        a = {s["name"] for s in le["symbols"] if s["name"]}
        b = {s["name"] for s in re_["symbols"] if s["name"]}
        d.metrics["exports_added"], d.metrics["exports_removed"] = sorted(b - a), sorted(a - b)
    if lst and rst:
        a = {s["value"] for s in lst["strings"]}
        b = {s["value"] for s in rst["strings"]}
        d.metrics["strings_added"], d.metrics["strings_removed"] = len(b - a), len(a - b)
    else:
        d.metrics["strings_added"] = d.metrics["strings_removed"] = None
    d.notes.append("data/behaviour features only; no semantic model in V1")
    return d


def _clusters(modified: set[int], feats: dict[int, dict[str, Any]]) -> list[list[int]]:
    """Group modified right-side functions connected through the call graph."""
    parent = {f: f for f in modified}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for f in modified:
        for c in feats.get(f, {}).get("callgraph", {}).get("callees", []):
            if c in modified:
                parent[find(f)] = find(c)
    groups: dict[int, list[int]] = {}
    for f in modified:
        groups.setdefault(find(f), []).append(f)
    return sorted((sorted(g) for g in groups.values()), key=lambda g: (-len(g), g[0]))


def _structural(
    ws: Workspace, run_id: str, lsha: str, rsha: str, lf: dict[str, Any] | None, rf: dict[str, Any] | None
) -> tuple[DimensionResult, list[list[int]]]:
    rows = ws.db.conn.execute(
        "SELECT decision, evidence_json, left_function_id, right_function_id FROM consensus_match"
        " WHERE analysis_run_id=? AND left_artifact_sha256=? AND right_artifact_sha256=?",
        (run_id, lsha, rsha),
    ).fetchall()
    if not rows or lf is None or rf is None:
        return DimensionResult(
            ChangeDimension.STRUCTURAL, M.NOT_MEASURED, notes=["no consensus for this component pair"]
        ), []
    lfe = {f["entry"]: f for f in lf["functions"]}
    rfe = {f["entry"]: f for f in rf["functions"]}
    counts: dict[str, int] = {}
    modified: set[int] = set()
    cyclo_deltas = []
    for r in rows:
        ev = json.loads(r["evidence_json"])
        side = "right_only" if ev.get("side") == "right-only" else r["decision"]
        counts[side] = counts.get(side, 0) + 1
        la, ra = ev.get("left_address"), ev.get("right_address")
        if (
            r["decision"] in ("STRONG", "PROBABLE")
            and la in lfe
            and ra in rfe
            and lfe[la]["instruction"]["normalized_hash"] != rfe[ra]["instruction"]["normalized_hash"]
        ):
            modified.add(ra)
            cyclo_deltas.append(rfe[ra]["cfg"]["cyclomatic"] - lfe[la]["cfg"]["cyclomatic"])
    n_left = len(lfe)
    d = DimensionResult(ChangeDimension.STRUCTURAL, M.MEASURED)
    d.metrics.update(
        {
            "functions_left": n_left,
            "functions_right": len(rfe),
            "decision_counts": dict(sorted(counts.items())),
            "modified_functions": len(modified),
            "modified_ratio": round(len(modified) / n_left, 6) if n_left else None,
            "unresolved_left": counts.get("UNRESOLVED", 0),
            "unresolved_right": counts.get("right_only", 0),
            "cyclomatic_delta_sum": sum(cyclo_deltas),
        }
    )
    d.notes.append("unresolved functions are neither removed nor new (spec §2)")
    clusters = _clusters(modified, rfe)
    d.metrics["clusters"] = len(clusters)
    return d, clusters


def _deployment(ws: Workspace, left_build: str, right_build: str) -> DimensionResult:
    def obs(b: str) -> list[str]:
        return [
            r[0]
            for r in ws.db.conn.execute(
                "SELECT observed_at FROM observation WHERE build_id=? AND observed_at IS NOT NULL ORDER BY observed_at",
                (b,),
            )
        ]

    lo, ro = obs(left_build), obs(right_build)
    if not lo or not ro:
        return DimensionResult(ChangeDimension.DEPLOYMENT, M.NOT_MEASURED, notes=["observation dates unknown"])
    try:
        gap = (date.fromisoformat(ro[0][:10]) - date.fromisoformat(lo[0][:10])).days
    except ValueError:
        gap = None
    return DimensionResult(
        ChangeDimension.DEPLOYMENT,
        M.MEASURED if gap is not None else M.PARTIAL,
        {"first_observed_gap_days": gap, "observations_left": len(lo), "observations_right": len(ro)},
    )


def _ecosystem(ws: Workspace, product_id: str, left_build: str, right_build: str) -> DimensionResult:
    def first(b: str) -> str | None:
        r = ws.db.conn.execute("SELECT min(observed_at) FROM observation WHERE build_id=?", (b,)).fetchone()
        return r[0] if r else None

    a, b = first(left_build), first(right_build)
    if a is None or b is None:
        return DimensionResult(ChangeDimension.ECOSYSTEM, M.NOT_MEASURED, notes=["observation dates unknown"])
    evs = correlated_events(ws, product_id, a, b)
    return DimensionResult(
        ChangeDimension.ECOSYSTEM,
        M.MEASURED,
        {"correlated_events": evs},
        notes=["external events are temporal correlations, never causes (ACET-CHG-002)"],
    )


def _reliability(ws: Workspace, run: Any, lf: dict[str, Any] | None, rf: dict[str, Any] | None) -> DimensionResult:
    missing = json.loads(run["missing_evidence_json"] or "[]")
    engines = json.loads(run["resolved_config_json"] or "{}").get("engines", {}).get("providers", {})
    unverified = sorted(k for k, v in engines.items() if v.get("available") and not v.get("verified"))
    q = [
        x["extraction_quality"]["code_coverage_ratio"]
        for x in (lf, rf)
        if x and x["extraction_quality"].get("code_coverage_ratio") is not None
    ]
    d = DimensionResult(
        ChangeDimension.ANALYSIS_RELIABILITY,
        M.MEASURED,
        {
            "run_coverage": run["coverage"],
            "missing_evidence": len(missing),
            "missing_processors": sorted({m["processor"] for m in missing}),
            "extraction_code_coverage_min": min(q) if q else None,
            "unverified_engines": unverified,
            "calibration": "NONE (classes only, ADR-0008)",
        },
    )
    level = "HIGH"
    if missing or (q and min(q) < 0.9) or unverified:
        level = "MEDIUM"
    if (run["coverage"] is not None and run["coverage"] < 0.6) or (q and min(q) < 0.5):
        level = "LOW"
    d.reliability_class = level
    return d


def detect_changes(ws: Workspace, compare_run_id: str) -> dict[str, Any]:
    ws.require_writable()
    run = ws.db.conn.execute("SELECT * FROM analysis_run WHERE id=?", (compare_run_id,)).fetchone()
    if run is None or run["scope_type"] != "compare":
        raise AcetError("ACET-NOTFOUND-001", f"compare run {compare_run_id}")
    left_build, right_build = run["scope_id"].split(":")
    product_id = ws.db.conn.execute("SELECT product_id FROM build WHERE id=?", (left_build,)).fetchone()[0]
    from acet.analysis.orchestrator import pair_components

    pairs, notes = pair_components(
        repo.build_artifacts(ws.db.conn, left_build), repo.build_artifacts(ws.db.conn, right_build)
    )
    roles = {c["sha256"]: c["role"] for c in repo.build_artifacts(ws.db.conn, right_build)}
    report: dict[str, Any] = {
        "run_id": compare_run_id,
        "rules": RULES,
        "components": [],
        "notes": notes,
        "global_score": None,
    }
    deployment = _deployment(ws, left_build, right_build)
    ecosystem = _ecosystem(ws, product_id, left_build, right_build)
    with ws.db.transaction() as tx:
        if tx.execute("SELECT 1 FROM detected_change WHERE analysis_run_id=? LIMIT 1", (compare_run_id,)).fetchone():
            raise AcetError("ACET-DOM-001", "changes already detected for this run (results are immutable)")
    for lsha, rsha in pairs:
        role = roles.get(rsha, "OTHER")
        lpe, rpe = derived_for_artifact(ws, "acet.pe", lsha), derived_for_artifact(ws, "acet.pe", rsha)
        lh, rh = derived_for_artifact(ws, "acet.hash", lsha), derived_for_artifact(ws, "acet.hash", rsha)
        lst, rst = derived_for_artifact(ws, "acet.strings", lsha), derived_for_artifact(ws, "acet.strings", rsha)
        lf, rf = derived_for_artifact(ws, "acet.features", lsha), derived_for_artifact(ws, "acet.features", rsha)
        structural, clusters = _structural(ws, compare_run_id, lsha, rsha, lf, rf)
        dims = [
            _binary(lpe, rpe, lh, rh),
            _build(lpe, rpe),
            structural,
            _semantic(lpe, rpe, lst, rst),
            deployment,
            ecosystem,
            _reliability(ws, run, lf, rf),
        ]
        rel = dims[-1].reliability_class
        baseline_metrics = {
            ChangeDimension.BINARY: dims[0].metrics.get("size_delta_ratio"),
            ChangeDimension.STRUCTURAL: structural.metrics.get("modified_ratio"),
            ChangeDimension.SEMANTIC: (len(dims[3].metrics["imports_added"]) + len(dims[3].metrics["imports_removed"]))
            if dims[3].metrics.get("imports_added") is not None
            else None,
        }
        with ws.db.transaction() as tx:
            for dim in dims:
                metric = baseline_metrics.get(dim.dimension)
                if dim.dimension in baseline_metrics:
                    hist = [
                        r[0]
                        for r in tx.execute(
                            "SELECT value FROM baseline_observation WHERE product_id=? AND component_role=? AND metric=?"
                            " ORDER BY seq",
                            (product_id, role, f"{RULES}:{dim.dimension.value}"),
                        )
                    ]
                    b = classify(abs(metric) if metric is not None else None, [abs(h) for h in hist])
                    dim.baseline, dim.severity_class = b.to_dict(), b.cls.value
                    if metric is not None:
                        tx.execute(
                            "INSERT INTO baseline_observation(id, product_id, component_role, metric, value,"
                            " analysis_run_id, seq) VALUES (?,?,?,?,?,?,?)",
                            (
                                uuid7(),
                                product_id,
                                role,
                                f"{RULES}:{dim.dimension.value}",
                                float(metric),
                                compare_run_id,
                                repo.next_seq(tx),
                            ),
                        )
                if dim.reliability_class == "UNKNOWN":
                    dim.reliability_class = rel
                tx.execute(
                    "INSERT INTO detected_change(id, analysis_run_id, change_type, severity_class, reliability_class,"
                    " evidence_json, dimension, measurement_state, component_role, cluster_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        uuid7(),
                        compare_run_id,
                        f"{dim.dimension.value}_CHANGE",
                        dim.severity_class,
                        dim.reliability_class,
                        stable_json(
                            {
                                **dim.to_dict(),
                                "left": lsha,
                                "right": rsha,
                                "clusters": clusters if dim.dimension is ChangeDimension.STRUCTURAL else None,
                            }
                        ).decode(),
                        dim.dimension.value,
                        dim.state.value,
                        role,
                        None,
                    ),
                )
            repo.audit(tx, "changes.detect", "analysis_run", compare_run_id, {"component": role})
        report["components"].append(
            {"role": role, "left": lsha, "right": rsha, "dimensions": [d.to_dict() for d in dims], "clusters": clusters}
        )
    return report


def list_changes(ws: Workspace, run_id: str) -> list[dict[str, Any]]:
    out = []
    for r in ws.db.conn.execute(
        "SELECT * FROM detected_change WHERE analysis_run_id=? ORDER BY component_role, dimension", (run_id,)
    ):
        d = dict(r)
        d["evidence"] = json.loads(d.pop("evidence_json"))
        out.append(d)
    return out
