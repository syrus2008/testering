"""Benchmark datasets (spec §40, ACET-BEN-001/006, ACC-027).

A dataset directory holds ``dataset.json`` (name, version, license), ``builds/<version>/``
and ``ground_truth.json``. Registration copies the ground truth into the workspace's
benchmark area, which analyzers never receive: workers only get build artifacts.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo


def dataset_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob("*") if x.is_file() and "golden" not in x.parts):
        h.update(p.relative_to(root).as_posix().encode())
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def register_dataset(ws: Workspace, root: Path) -> str:
    ws.require_writable()
    meta_p, gt_p = root / "dataset.json", root / "ground_truth.json"
    if not meta_p.is_file() or not gt_p.is_file():
        raise AcetError("ACET-IMP-005", "dataset needs dataset.json and ground_truth.json")
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    for k in ("name", "version", "license"):
        if not meta.get(k):
            raise AcetError("ACET-IMP-005", f"dataset.json: missing {k}")
    dh = dataset_hash(root)
    row = ws.db.conn.execute("SELECT id FROM benchmark_dataset WHERE dataset_hash=?", (dh,)).fetchone()
    if row:
        return str(row["id"])
    did = uuid7()
    dest = ws.path / "benchmark" / did
    dest.mkdir(parents=True)
    shutil.copyfile(gt_p, dest / "ground_truth.json")
    shutil.copyfile(meta_p, dest / "dataset.json")
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO benchmark_dataset(id, name, version, dataset_hash, license, ground_truth_relpath,"
            " created_at) VALUES (?,?,?,?,?,?,?)",
            (
                did,
                meta["name"],
                str(meta["version"]),
                dh,
                meta["license"],
                (dest / "ground_truth.json").relative_to(ws.path).as_posix(),
                utc_now_iso(),
            ),
        )
        repo.audit(tx, "benchmark.register", "benchmark_dataset", did, {"name": meta["name"]})
    return did


def load_ground_truth(ws: Workspace, dataset_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    row = ws.db.conn.execute("SELECT * FROM benchmark_dataset WHERE id=?", (dataset_id,)).fetchone()
    if row is None:
        raise AcetError("ACET-NOTFOUND-001", f"dataset {dataset_id}")
    gt = json.loads((ws.path / row["ground_truth_relpath"]).read_text(encoding="utf-8"))
    return dict(row), gt
