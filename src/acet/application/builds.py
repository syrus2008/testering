"""Build use cases: listing, details, integrity gate, trash (soft delete)."""

from __future__ import annotations

from typing import Any

from acet.application.workspace import Workspace
from acet.domain.enums import IntegrityState
from acet.domain.error_codes import AcetError
from acet.domain.state_machines import ARTIFACT
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo


def list_builds(ws: Workspace, product_id: str | None = None, *, include_deleted: bool = False) -> list[dict[str, Any]]:
    sql = """SELECT b.id, b.product_id, b.build_fingerprint, b.arch, b.status, b.created_at, b.deleted_at,
                    r.version_label, r.channel,
                    (SELECT min(observed_at) FROM observation o WHERE o.build_id=b.id) AS first_observed,
                    (SELECT max(observed_at) FROM observation o WHERE o.build_id=b.id) AS last_observed,
                    (SELECT count(*) FROM observation o WHERE o.build_id=b.id) AS observations
             FROM build b LEFT JOIN release r ON r.id=b.release_id WHERE 1=1"""
    args: list[Any] = []
    if product_id:
        sql += " AND b.product_id=?"
        args.append(product_id)
    if not include_deleted:
        sql += " AND b.deleted_at IS NULL"
    sql += " ORDER BY b.created_at"
    return [dict(r) for r in ws.db.conn.execute(sql, args).fetchall()]


def get_build(ws: Workspace, build_id: str) -> dict[str, Any]:
    row = repo.row_to_dict(ws.db.conn.execute("SELECT * FROM build WHERE id=?", (build_id,)).fetchone())
    if row is None:
        raise AcetError("ACET-NOTFOUND-001", f"build {build_id}")
    row["components"] = repo.build_artifacts(ws.db.conn, build_id)
    row["observations"] = [
        dict(r)
        for r in ws.db.conn.execute(
            "SELECT id, observed_at, time_precision, source_type, source_label, imported_at"
            " FROM observation WHERE build_id=? ORDER BY imported_at",
            (build_id,),
        )
    ]
    return row


def verify_build_artifacts(ws: Workspace, build_id: str) -> list[str]:
    """Integrity gate run before any analysis (ACC-008, ACET-STO-002).

    Re-hashes every artifact of the build. Corrupted/missing blobs are marked
    CORRUPTED and an ``AcetError`` blocks the analysis.
    """
    comps = repo.build_artifacts(ws.db.conn, build_id)
    bad: list[str] = []
    for c in comps:
        if not ws.store.verify(c["sha256"]):
            bad.append(c["sha256"])
    if bad and ws.writable:
        with ws.db.transaction() as tx:
            for sha in sorted(set(bad)):
                cur = tx.execute("SELECT integrity_state FROM artifact WHERE sha256=?", (sha,)).fetchone()
                if cur["integrity_state"] != IntegrityState.CORRUPTED.value:
                    ARTIFACT.check(cur["integrity_state"], IntegrityState.CORRUPTED.value)
                    tx.execute(
                        "UPDATE artifact SET integrity_state=? WHERE sha256=?", (IntegrityState.CORRUPTED.value, sha)
                    )
                    repo.audit(tx, "artifact.corrupted", "artifact", sha, {"build_id": build_id})
    if bad:
        code = "ACET-STO-002" if all(ws.store.path_for(s).exists() for s in bad) else "ACET-STO-001"
        raise AcetError(code, f"{len(bad)} artifact(s) failed verification", data={"artifacts": sorted(set(bad))})
    return [c["sha256"] for c in comps]


def soft_delete_build(ws: Workspace, build_id: str) -> None:
    """Soft delete → Trash (ACET-RET-001, ACC-036). Bytes are never touched here."""
    ws.require_writable()
    with ws.db.transaction() as tx:
        cur = tx.execute("UPDATE build SET deleted_at=? WHERE id=? AND deleted_at IS NULL", (utc_now_iso(), build_id))
        if cur.rowcount != 1:
            raise AcetError("ACET-NOTFOUND-001", f"active build {build_id}")
        repo.audit(tx, "build.soft_delete", "build", build_id, {})


def restore_build(ws: Workspace, build_id: str) -> None:
    ws.require_writable()
    with ws.db.transaction() as tx:
        cur = tx.execute("UPDATE build SET deleted_at=NULL WHERE id=? AND deleted_at IS NOT NULL", (build_id,))
        if cur.rowcount != 1:
            raise AcetError("ACET-NOTFOUND-001", f"trashed build {build_id}")
        repo.audit(tx, "build.restore", "build", build_id, {})
