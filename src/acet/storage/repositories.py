"""Thin repositories over the SQLite schema. All functions take an open connection
inside a caller-managed transaction (transaction boundaries: spec §101)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from acet.domain.canonical import canonical_json
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso


def audit(
    conn: sqlite3.Connection,
    event_type: str,
    target_type: str | None = None,
    target_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> str:
    """Append an audit event (ACC-035). Payloads must not contain full local paths."""
    aid = uuid7()
    conn.execute(
        "INSERT INTO audit_event(id, event_type, target_type, target_id, created_at, payload_json)"
        " VALUES (?,?,?,?,?,?)",
        (aid, event_type, target_type, target_id, utc_now_iso(), canonical_json(payload or {}).decode()),
    )
    return aid


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return None if row is None else {k: row[k] for k in row.keys()}  # noqa: SIM118


def get_product(conn: sqlite3.Connection, product_id: str) -> dict[str, Any] | None:
    return row_to_dict(conn.execute("SELECT * FROM product WHERE id=?", (product_id,)).fetchone())


def find_product(conn: sqlite3.Connection, ref: str) -> dict[str, Any] | None:
    """Lookup by id, then by exact name."""
    p = get_product(conn, ref)
    if p is None:
        rows = conn.execute("SELECT * FROM product WHERE name=?", (ref,)).fetchall()
        if len(rows) == 1:
            p = row_to_dict(rows[0])
    return p


def get_or_create_release(conn: sqlite3.Connection, product_id: str, version_label: str, channel: str | None) -> str:
    row = conn.execute(
        "SELECT id FROM release WHERE product_id=? AND version_label=? AND channel IS ?",
        (product_id, version_label, channel),
    ).fetchone()
    if row:
        return str(row["id"])
    rid = uuid7()
    conn.execute(
        "INSERT INTO release(id, product_id, version_label, channel) VALUES (?,?,?,?)",
        (rid, product_id, version_label, channel),
    )
    return rid


def build_by_fingerprint(conn: sqlite3.Connection, fingerprint: str) -> dict[str, Any] | None:
    return row_to_dict(conn.execute("SELECT * FROM build WHERE build_fingerprint=?", (fingerprint,)).fetchone())


def build_artifacts(conn: sqlite3.Connection, build_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT c.id AS component_id, c.role, c.role_confidence, c.label, c.ordinal,
                  ca.purpose, a.sha256, a.size_bytes, a.format, a.arch, a.integrity_state
           FROM component c
           JOIN component_artifact ca ON ca.component_id = c.id
           JOIN artifact a ON a.sha256 = ca.artifact_sha256
           WHERE c.build_id = ? ORDER BY c.role, a.sha256, c.ordinal""",
        (build_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def loads(text: str | None) -> Any:
    return None if text is None else json.loads(text)
