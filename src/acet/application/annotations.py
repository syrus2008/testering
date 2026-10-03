"""Annotations and human assertions (spec §116, ACET-HUM-001, ACC-035/131/132).

Human input never mutates automatic results and never becomes benchmark ground truth.
"""

from __future__ import annotations

from typing import Any

from acet.application.workspace import Workspace
from acet.domain.canonical import stable_json
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo

TARGETS = (
    "product",
    "build",
    "artifact",
    "function_instance",
    "lineage",
    "analysis_run",
    "consensus_match",
    "detected_change",
    "external_event",
)
ASSERTIONS = ("ACCEPT_AUTOMATIC", "HUMAN_ASSERTION", "NEEDS_EVIDENCE", "DISMISS_FROM_INVESTIGATION")


def add_annotation(ws: Workspace, target_type: str, target_id: str, body: str, *, author: str | None = None) -> str:
    ws.require_writable()
    if target_type not in TARGETS:
        raise AcetError("ACET-IMP-005", f"target_type must be one of {TARGETS}")
    if not body.strip():
        raise AcetError("ACET-IMP-005", "empty annotation")
    aid = uuid7()
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO annotation(id, target_type, target_id, author_id, body, created_at) VALUES (?,?,?,?,?,?)",
            (aid, target_type, target_id, author, body, utc_now_iso()),
        )
        repo.audit(tx, "annotation.add", target_type, target_id, {"annotation_id": aid})
    return aid


def delete_annotation(ws: Workspace, annotation_id: str) -> None:
    """Soft delete: history is kept (§6 HUMAN = historized)."""
    with ws.db.transaction() as tx:
        cur = tx.execute(
            "UPDATE annotation SET deleted_at=? WHERE id=? AND deleted_at IS NULL", (utc_now_iso(), annotation_id)
        )
        if cur.rowcount != 1:
            raise AcetError("ACET-NOTFOUND-001", f"annotation {annotation_id}")
        repo.audit(tx, "annotation.delete", "annotation", annotation_id, {})


def add_assertion(
    ws: Workspace,
    target_type: str,
    target_id: str,
    assertion: str,
    *,
    reason: str | None = None,
    evidence_refs: list[str] | None = None,
    author: str | None = None,
) -> str:
    ws.require_writable()
    if assertion not in ASSERTIONS:
        raise AcetError("ACET-IMP-005", f"assertion must be one of {ASSERTIONS}")
    hid = uuid7()
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO human_assertion(id, target_type, target_id, assertion, reason, evidence_refs_json,"
            " author_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                hid,
                target_type,
                target_id,
                assertion,
                reason,
                stable_json(evidence_refs or []).decode(),
                author,
                utc_now_iso(),
            ),
        )
        repo.audit(tx, "assertion.add", target_type, target_id, {"assertion": assertion})
    return hid


def list_annotations(ws: Workspace, target_type: str, target_id: str) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in ws.db.conn.execute(
            "SELECT * FROM annotation WHERE target_type=? AND target_id=? AND deleted_at IS NULL ORDER BY created_at",
            (target_type, target_id),
        )
    ]
