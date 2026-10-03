"""Product use cases."""

from __future__ import annotations

from typing import Any

from acet.application.workspace import Workspace
from acet.domain.canonical import canonical_json
from acet.domain.ids import uuid7
from acet.domain.product_profile import ProductProfile
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo


def create_product(
    ws: Workspace, name: str, *, vendor: str | None = None, profile: dict[str, Any] | None = None
) -> str:
    ws.require_writable()
    prof = ProductProfile.parse(profile) if profile is not None else ProductProfile.empty(name)
    pid = uuid7()
    with ws.db.transaction() as conn:
        conn.execute(
            "INSERT INTO product(id, workspace_id, name, vendor, profile_json, created_at) VALUES (?,?,?,?,?,?)",
            (pid, ws.id, name, vendor, canonical_json(prof.raw).decode(), utc_now_iso()),
        )
        repo.audit(conn, "product.create", "product", pid, {"name": name})
    return pid


def list_products(ws: Workspace) -> list[dict[str, Any]]:
    rows = ws.db.conn.execute("SELECT id, name, vendor, created_at FROM product ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]
