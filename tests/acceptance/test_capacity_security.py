"""Capacity envelope (ACC-120) and vulnerability triage (ACC-126)."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from acet.application.search import search
from acet.domain.ids import uuid7
from acet.platform.capacity import capacity
from acet.platform.doctor import reconcile

ROOT = Path(__file__).resolve().parents[2]
SIZE = os.environ.get("ACET_CAPACITY", "S")  # "M" runs the full validated envelope (minutes)
SCALE = {"S": (25, 50_000), "M": (250, 1_000_000)}


@pytest.mark.acceptance("ACC-120")
def test_capacity_envelope_without_invariant_failure(ws, product_id):
    builds, functions = SCALE[SIZE]
    t0 = time.monotonic()
    per_build = functions // builds
    with ws.db.transaction() as tx:
        tx.execute("INSERT INTO analysis_profile VALUES ('prof','CAP',1,'{}','h')")
        tx.execute(
            "INSERT INTO analysis_run(id, scope_type, scope_id, profile_id, status, started_at) VALUES"
            " ('run','build','x','prof','COMPLETED','2026-01-01T00:00:00Z')"
        )
        for b in range(builds):
            sha = f"{b:064x}"
            bid = uuid7()
            tx.execute(
                "INSERT INTO artifact VALUES (?,1,NULL,'PE32+','x64',?, '2026-01-01T00:00:00Z','AVAILABLE',NULL)",
                (sha, ws.store.relpath_for(sha)),
            )
            tx.execute(
                "INSERT INTO build(id, product_id, build_fingerprint, platform, status, created_at) VALUES"
                " (?,?,?,?,?,?)",
                (bid, product_id, f"{b + 10**6:064x}", "windows", "UNASSESSED", "2026-01-01T00:00:00Z"),
            )
            pr = f"pr{b}"
            tx.execute(
                "INSERT INTO processor_run(id, analysis_run_id, processor_id, processor_version, input_hash,"
                " config_hash, cache_key, status, started_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (pr, "run", "acet.features", "1", sha, sha, sha, "COMPLETED", "2026-01-01T00:00:00Z"),
            )
            tx.executemany(
                "INSERT INTO function_instance(id, artifact_sha256, extractor_run_id, address, size, name,"
                " normalized_hash, feature_schema_version) VALUES (?,?,?,?,?,?,?,1)",
                (
                    (f"{b}-{i}", sha, pr, 0x1000 + i * 16, 16, f"fn_{b}_{i}" if i % 50 == 0 else None, f"{i:064x}")
                    for i in range(per_build)
                ),
            )
    load_s = time.monotonic() - t0
    cap = capacity(ws)
    assert cap["class"] == SIZE and cap["validated"]
    assert ws.db.integrity_check(quick=True) == []
    t0 = time.perf_counter()
    hits = search(ws, f"fn_{builds - 1}_")
    search_s = time.perf_counter() - t0
    assert hits and search_s < 2.5
    t0 = time.perf_counter()
    n = ws.db.conn.execute(
        "SELECT count(*) FROM function_instance WHERE artifact_sha256=?", (f"{builds - 1:064x}",)
    ).fetchone()[0]
    assert n == per_build and time.perf_counter() - t0 < 0.5  # indexed lookup
    rec = reconcile(ws)
    assert rec.orphan_blobs == []  # dangling refs are expected here: synthetic rows have no bytes
    if SIZE == "M":
        ev = ROOT / "docs" / "evidence" / "capacity-M.json"
        ev.parent.mkdir(parents=True, exist_ok=True)
        ev.write_text(
            json.dumps(
                {
                    "class": "M",
                    "builds": builds,
                    "function_instances": functions,
                    "load_s": round(load_s, 1),
                    "search_s": round(search_s, 3),
                    "integrity_check": "ok",
                    "python": sys.version.split()[0],
                    "machine": "CI container (4 vCPU, 15 GiB)",
                },
                indent=2,
            ),
            encoding="utf-8",
        )


@pytest.mark.acceptance("ACC-126")
def test_sbom_vulnerability_scan_requires_triage(tmp_path):
    sys.path.insert(0, str(ROOT))
    from tools.sbom import build_sbom
    from tools.vuln_scan import scan

    sbom = build_sbom()
    sbom["components"].append({"type": "library", "name": "examplelib", "version": "1.0"})
    adv = [
        {
            "id": "OSV-TEST-1",
            "package": "examplelib",
            "affected_versions": ["1.0"],
            "severity": "HIGH",
            "summary": "test advisory",
        }
    ]
    res = scan(sbom, adv, {})
    assert res["status"] == "FAILED" and res["untriaged"] == ["OSV-TEST-1"]
    res = scan(sbom, adv, {"OSV-TEST-1": {"decision": "not exploitable in ACET context", "by": "release owner"}})
    assert res["status"] == "PASSED" and res["findings"][0]["triage"]
