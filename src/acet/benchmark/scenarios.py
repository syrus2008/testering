"""Scenario corpora for lineage (datasets/resurrection): each scenario is an ordered sequence of
builds of one component with ground truth from linker maps; scored with ``lineage_metrics``."""

from __future__ import annotations

import hashlib
import json
from itertools import pairwise
from pathlib import Path
from typing import Any

from acet.analysis.orchestrator import compare_builds
from acet.application.products import create_product
from acet.application.workspace import Workspace
from acet.benchmark.metrics import lineage_metrics
from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build
from acet.lineage.builder import build_lineage


def load(root: Path) -> dict[str, Any]:
    gt: dict[str, Any] = json.loads((root / "ground_truth.json").read_text(encoding="utf-8"))
    return gt


def as_benchmark_gt(gt: dict[str, Any], scenario: str) -> dict[str, Any]:
    """Scenario ground truth in the Benchmark Lab format consumed by ``lineage_metrics``."""
    comp, spec = gt["component"], gt["scenarios"][scenario]
    return {
        "versions": spec["versions"],
        "components": [comp],
        "functions": {comp: {v: gt["functions"][v] for v in spec["versions"]}},
        "transitions": [{**t, "component": comp, "splits": [], "merges": []} for t in spec["transitions"]],
    }


def run_scenario(ws: Workspace, root: Path, scenario: str, profile: str = "STANDARD@1") -> dict[str, Any]:
    gt = load(root)
    comp, spec = gt["component"], gt["scenarios"][scenario]
    pid = create_product(ws, f"{gt['dataset']} {scenario}")
    builds: list[str] = []
    sha_to: dict[str, tuple[str, str]] = {}
    for i, v in enumerate(spec["versions"]):
        res = import_build(
            ws,
            ImportRequest(
                [root / "builds" / v],
                pid,
                release_label=v,
                observed_at=f"2001-01-{i + 1:02d}",
                on_duplicate=DuplicatePolicy.ADD_OBSERVATION,
            ),
        )
        builds.append(res.build_id)
        sha_to[hashlib.sha256((root / "builds" / v / comp).read_bytes()).hexdigest()] = (comp, v)
    for a, b in pairwise(builds):
        compare_builds(ws, a, b, profile)
    lin = build_lineage(ws, pid, builds, incremental=False)
    return {
        "scenario": scenario,
        "builds": builds,
        "lineage_run": lin.run_id,
        "relations": lin.relations,
        "lineage": lineage_metrics(ws, lin.run_id, as_benchmark_gt(gt, scenario), sha_to),
    }
