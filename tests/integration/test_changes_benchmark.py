"""Change detection, baselines, events, timeline (P9) and Benchmark Lab / calibration (P10)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acet.analysis.orchestrator import compare_builds
from acet.benchmark.calibration import calibrate, display_confidence, pav
from acet.benchmark.gates import check_gates
from acet.benchmark.runner import run_benchmark, split_transitions
from acet.changes.baseline import BaselineClass, classify
from acet.changes.detector import detect_changes, list_changes
from acet.changes.events import add_event, correlated_events, evidence_strength
from acet.changes.timeline import product_timeline
from acet.domain.error_codes import AcetError
from acet.ingest.importer import ImportRequest, import_build

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "datasets" / "demo"


@pytest.fixture
def replay(monkeypatch):
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DEMO / "golden" / "ghidra"))
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def compared(ws, product_id, replay):
    b = [
        import_build(
            ws,
            ImportRequest([DEMO / "builds" / f"v{v}"], product_id, release_label=str(v), observed_at=f"2026-0{v}-01"),
        ).build_id
        for v in (1, 2)
    ]
    return b, compare_builds(ws, b[0], b[1], "STANDARD@1")


@pytest.mark.acceptance("ACC-016", "ACC-017", "ACC-071")
def test_changes_are_separate_dimensions_with_unknowns(ws, product_id, compared):
    _b, run = compared
    report = detect_changes(ws, run.run_id)
    assert report["global_score"] is None
    comp = next(c for c in report["components"] if c["role"] == "USER_MODULE")
    dims = {d["dimension"]: d for d in comp["dimensions"]}
    assert set(dims) == {"BINARY", "BUILD", "STRUCTURAL", "SEMANTIC", "DEPLOYMENT", "ECOSYSTEM", "ANALYSIS_RELIABILITY"}
    assert dims["BINARY"]["metrics"]["tlsh_distance"] is None  # not measured ≠ 0
    assert dims["STRUCTURAL"]["metrics"]["modified_functions"] >= 2
    assert dims["STRUCTURAL"]["severity_class"] == "UNKNOWN"  # insufficient history, not NORMAL
    rel = dims["ANALYSIS_RELIABILITY"]
    assert rel["metrics"]["missing_processors"] == ["ghidriff.diff@1"]
    assert "ghidra" in rel["metrics"]["unverified_engines"]  # replay is never a verified engine
    assert rel["reliability_class"] in ("MEDIUM", "LOW")
    assert dims["DEPLOYMENT"]["metrics"]["first_observed_gap_days"] == 31
    rows = list_changes(ws, run.run_id)
    assert all(r["measurement_state"] for r in rows) and not any("score" in r for r in rows)
    with pytest.raises(AcetError):
        detect_changes(ws, run.run_id)  # immutable once written


def test_baseline_classes():
    assert classify(0.5, [0.1] * 3).cls is BaselineClass.UNKNOWN
    hist = [0.10, 0.12, 0.11, 0.09, 0.10, 0.13, 0.11]
    assert classify(0.11, hist).cls is BaselineClass.NORMAL
    assert classify(0.9, hist).cls is BaselineClass.EXTREME
    assert classify(None, hist).cls is BaselineClass.UNKNOWN


@pytest.mark.acceptance("ACC-040", "ACC-096", "ACC-145")
def test_external_events_are_correlations_only(ws, product_id, compared):
    _builds, run = compared
    add_event(
        ws,
        product_id,
        event_type="patch-notes",
        summary="Vendor patch notes",
        source_class="OFFICIAL",
        occurred_at="2026-01-20",
        source_ref="https://example.invalid/notes",
        corroboration="MULTIPLE_SOURCES",
    )
    add_event(
        ws, product_id, event_type="rumour", summary="Forum post", source_class="COMMUNITY", occurred_at="2026-01-25"
    )
    evs = correlated_events(ws, product_id, "2026-01-01", "2026-02-01")
    assert len(evs) == 2
    assert all(e["causal_claim"] is False and "not a causal claim" in e["relation"] for e in evs)
    assert {e["evidence_strength"] for e in evs} <= {"LOW", "MEDIUM"}
    assert evidence_strength(None, None, "MULTIPLE_SOURCES") == "LOW"
    assert evidence_strength("OFFICIAL", "ref", "MULTIPLE_SOURCES") == "MEDIUM"  # never HIGH
    with pytest.raises(AcetError):
        add_event(ws, product_id, event_type="x", summary="y", source_class="RANDOM")
    report = detect_changes(ws, run.run_id)
    eco = next(d for d in report["components"][0]["dimensions"] if d["dimension"] == "ECOSYSTEM")
    assert len(eco["metrics"]["correlated_events"]) == 2
    tl = product_timeline(ws, product_id)
    assert [i["kind"] for i in tl].count("external_event") == 2 and any(i["kind"] == "comparison" for i in tl)


@pytest.mark.acceptance("ACC-027", "ACC-133", "ACC-134")
def test_benchmark_blind_split_and_manifest(ws, replay):
    res = run_benchmark(ws, DEMO, "STANDARD@1", split="calibration")
    m = res["manifest"]
    for k in ("dataset_hash", "ground_truth_sha256", "split", "profile", "engines", "acet_version", "transitions"):
        assert m[k] is not None
    assert m["labels_provided_to_detector"] is False
    assert all(t[1:] == ["v1", "v2"] for t in m["transitions"])  # calibration split = first step only
    test_split = split_transitions(json.loads((DEMO / "ground_truth.json").read_text())["transitions"], "test")
    assert {(t["from"], t["to"]) for t in test_split} == {("v2", "v3")}  # disjoint from calibration
    # Blind: no worker request ever referenced the ground truth.
    for prq in ws.path.rglob("request.json"):
        assert "ground_truth" not in prq.read_text()
    for row in ws.db.conn.execute("SELECT resolved_config_json FROM analysis_run"):
        assert "ground_truth" not in (row[0] or "")


@pytest.mark.acceptance("ACC-050")
def test_benchmark_metrics_and_regression_gates(ws, replay):
    res = run_benchmark(ws, DEMO, "STANDARD@1")
    s = res["summary"]
    assert s["precision"] == 1.0 and s["recall"] >= 0.8 and s["lineage"]["purity"] == 1.0
    baseline = json.loads((ROOT / "benchmarks" / "demo-STANDARD@1-replay.json").read_text())
    gates = check_gates(s, baseline)
    assert gates and all(g["ok"] for g in gates), gates
    worse = {**s, "recall": s["recall"] - 0.2}
    assert not all(g["ok"] for g in check_gates(worse, baseline))


@pytest.mark.acceptance("ACC-028", "ACC-068", "ACC-069", "ACC-070", "ACC-146", "ACC-147")
def test_calibration_is_contextual_and_ood_shows_no_probability(ws, replay):
    assert display_confidence(ws, "acet.featurematch", "any", 0.9).kind == "class"  # nothing calibrated yet
    res = run_benchmark(ws, DEMO, "STANDARD@1", split="calibration")
    with pytest.raises(AcetError):
        calibrate(ws, run_benchmark(ws, DEMO, "STANDARD@1", split="test")["benchmark_run_id"], "acet.featurematch")
    # Same-context observations give one profile; a run spanning two contexts gives two separate mappings.
    assert len(calibrate(ws, res["benchmark_run_id"], "acet.featurematch", min_samples=5)) == 1
    row = ws.db.conn.execute("SELECT * FROM benchmark_run WHERE id=?", (res["benchmark_run_id"],)).fetchone()
    metrics = json.loads(row["metrics_json"])
    obs = metrics["observations"]
    metrics["observations"] = [
        [e, sc, ok if i % 2 else (not ok), "ctx=B" if i % 2 else "ctx=A"] for i, (e, sc, ok, _k) in enumerate(obs)
    ]
    from acet.domain.canonical import stable_json
    from acet.domain.ids import uuid7

    rid = uuid7()
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO benchmark_run VALUES (?,?,?,?,?,?,?)",
            (
                rid,
                row["dataset_id"],
                row["profile_ref"],
                "calibration",
                row["manifest_json"],
                stable_json(metrics).decode(),
                row["created_at"],
            ),
        )
    ids = calibrate(ws, rid, "acet.featurematch", min_samples=3)
    maps = dict(
        ws.db.conn.execute(
            "SELECT context_key, mapping_json FROM calibration_profile WHERE id IN (?,?)", tuple(ids)
        ).fetchall()
    )
    assert set(maps) == {"ctx=A", "ctx=B"} and maps["ctx=A"] != maps["ctx=B"]
    key = "ctx=B"
    shown = display_confidence(ws, "acet.featurematch", key, 0.95)
    assert shown.kind == "probability" and shown.state == "CALIBRATED" and 0 <= shown.value <= 1
    ood = display_confidence(ws, "acet.featurematch", "format=ELF|architecture=arm64", 0.95)
    assert ood.kind == "class" and ood.state == "OUT_OF_DISTRIBUTION" and ood.value is None
    assert display_confidence(ws, "acet.featurematch", "format=ELF", 0.95, ood_policy="abstain").abstain
    raw_before = ws.db.conn.execute("SELECT count(*), sum(raw_score) FROM matcher_result").fetchone()
    calibrate(ws, res["benchmark_run_id"], "acet.featurematch", min_samples=10_000)  # unvalidated
    assert ws.db.conn.execute("SELECT count(*), sum(raw_score) FROM matcher_result").fetchone() == raw_before


def test_pav_is_monotonic():
    m = pav([(0.1, False), (0.2, True), (0.3, False), (0.8, True), (0.9, True), (0.95, False)])
    precs = [p for _u, p, _n in m]
    assert precs == sorted(precs)
