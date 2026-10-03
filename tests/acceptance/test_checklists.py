"""ACET-CLOSE-001 / ACC-101: every mandatory subsystem answers all 21 dimensions (or NOT_APPLICABLE with reason)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANDATORY = [
    "Installer",
    "Updater",
    "Engine Pack",
    "Workspace",
    "SQLite",
    "Artifact Store",
    "Importer",
    "Archive Import",
    "PE Parser",
    "Ghidra Provider",
    "Ghidriff Provider",
    "BinExport Provider",
    "BinDiff Provider",
    "QBinDiff Provider",
    "External Diaphora",
    "Normalizer",
    "Matcher Normalizer",
    "Consensus",
    "Lineage",
    "Change Detector",
    "Baseline",
    "External Events",
    "Jobs",
    "Worker Supervisor",
    "Cache",
    "Backup",
    "Restore",
    "Reconcile",
    "Cleanup",
    "Reports",
    "ACETPack",
    "CLI",
    "UI",
    "Doctor",
    "Logging",
    "Audit",
    "Benchmark",
    "Calibration",
    "Product Profiles",
]


@pytest.mark.acceptance("ACC-101")
def test_21_dimension_checklists_complete():
    data = json.loads((ROOT / "docs" / "closure" / "subsystem-checklists.json").read_text(encoding="utf-8"))
    dims = data["dimensions"]
    assert len(dims) == 21
    assert sorted(data["subsystems"]) == sorted(MANDATORY)
    for name, entry in data["subsystems"].items():
        for d in dims:
            v = entry.get(d, "")
            assert v and (not v.startswith("NOT_APPLICABLE") or len(v) > len("NOT_APPLICABLE: ") + 3), (name, d)
        for test in entry["test"].split(","):
            path = test.strip().split(" ")[0]
            if path.startswith("tests/"):
                assert (ROOT / path).exists() or (ROOT / "tests" / path.split("/")[-1]).exists(), (name, path)
