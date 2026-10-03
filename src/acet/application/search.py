"""Global search (Ctrl+K, spec §28/§108, ACC-020/119). Secondary indexes only; all rebuildable."""

from __future__ import annotations

import re
from typing import Any

from acet.application.workspace import Workspace

MAX = 50


def rebuild_indexes(ws: Workspace) -> None:
    """ACET-SRCH-001: rebuild the annotation FTS index from the canonical table."""
    with ws.db.transaction() as tx:
        tx.execute("DELETE FROM annotation_fts")
        tx.execute(
            "INSERT INTO annotation_fts(body, annotation_id) SELECT body, id FROM annotation WHERE deleted_at IS NULL"
        )


def search(ws: Workspace, query: str, limit: int = MAX) -> list[dict[str, Any]]:
    q = query.strip()
    if not q:
        return []
    c = ws.db.conn
    out: list[dict[str, Any]] = []
    like = f"%{q}%"
    hexq = q.lower()
    if re.fullmatch(r"[0-9a-f]{4,64}", hexq):
        for r in c.execute(
            "SELECT sha256, format, integrity_state FROM artifact WHERE sha256 >= ? AND sha256 < ? LIMIT ?",
            (hexq, hexq + "g", limit),
        ):
            out.append(
                {
                    "kind": "artifact",
                    "id": r["sha256"],
                    "title": f"artifact {r['sha256'][:16]}…",
                    "detail": f"{r['format']} {r['integrity_state']}",
                }
            )
        for r in c.execute(
            "SELECT id, build_fingerprint FROM build WHERE build_fingerprint >= ? AND build_fingerprint < ? LIMIT ?",
            (hexq, hexq + "g", limit),
        ):
            out.append({"kind": "build", "id": r["id"], "title": f"build fingerprint {r['build_fingerprint'][:16]}…"})
    for r in c.execute(
        "SELECT b.id, r.version_label, r.channel FROM build b LEFT JOIN release r ON r.id=b.release_id"
        " WHERE b.id LIKE ? OR r.version_label LIKE ? OR r.channel LIKE ? LIMIT ?",
        (like, like, like, limit),
    ):
        out.append(
            {
                "kind": "build",
                "id": r["id"],
                "title": f"build {r['version_label'] or r['id'][:8]}",
                "detail": r["channel"],
            }
        )
    for r in c.execute("SELECT id, name FROM product WHERE name LIKE ? LIMIT ?", (like, limit)):
        out.append({"kind": "product", "id": r["id"], "title": r["name"]})
    for r in c.execute(
        "SELECT id, name, address, artifact_sha256 FROM function_instance WHERE name LIKE ? LIMIT ?", (like, limit)
    ):
        out.append({"kind": "function", "id": r["id"], "title": r["name"], "detail": hex(r["address"])})
    for r in c.execute(
        "SELECT id, label, component_role FROM lineage WHERE id LIKE ? OR label LIKE ? LIMIT ?", (like, like, limit)
    ):
        out.append(
            {
                "kind": "lineage",
                "id": r["id"],
                "title": f"lineage {r['label'] or r['id'][:8]}",
                "detail": r["component_role"],
            }
        )
    fts = " ".join(f'"{t}"' for t in re.findall(r"\w+", q, re.UNICODE)[:8])
    if fts:
        for r in c.execute(
            "SELECT a.id, a.body, a.target_type, a.target_id FROM annotation_fts f JOIN annotation a"
            " ON a.id=f.annotation_id WHERE annotation_fts MATCH ? AND a.deleted_at IS NULL LIMIT ?",
            (fts, limit),
        ):
            out.append(
                {
                    "kind": "annotation",
                    "id": r["id"],
                    "title": r["body"][:80],
                    "detail": f"{r['target_type']} {r['target_id'][:8]}",
                }
            )
    seen: set[tuple[str, str]] = set()
    uniq = []
    for item in out:
        k = (item["kind"], item["id"])
        if k not in seen:
            seen.add(k)
            uniq.append(item)
    return uniq[:limit]
