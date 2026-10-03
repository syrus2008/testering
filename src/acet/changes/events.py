"""External events (spec §83, ACET-EVT-001/002, ACC-040/096/145).

Events are sourced context. Their evidence strength is capped: never HIGH, and an
event without a source class or reference cannot exceed LOW. Proximity in time is
always worded as a temporal correlation — never as a cause.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.enums import SourceClass
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.timeutil import parse_external_timestamp, utc_now_iso
from acet.storage import repositories as repo

CORRELATION_WORDING = "temporal correlation (not a causal claim)"
CORROBORATION = ("UNCORROBORATED", "SINGLE_SOURCE", "MULTIPLE_SOURCES")


def evidence_strength(source_class: str | None, source_ref: str | None, corroboration: str) -> str:
    """ACC-096: no class/source ⇒ LOW. Even official + corroborated stays MEDIUM (correlation only)."""
    if not source_class or not source_ref:
        return "LOW"
    if source_class in (SourceClass.OFFICIAL, SourceClass.RESEARCH) and corroboration != "UNCORROBORATED":
        return "MEDIUM"
    return "LOW"


def add_event(
    ws: Workspace,
    product_id: str,
    *,
    event_type: str,
    summary: str,
    source_class: str,
    occurred_at: str | None = None,
    source_ref: str | None = None,
    corroboration: str = "UNCORROBORATED",
) -> str:
    ws.require_writable()
    try:
        sc = SourceClass(source_class)
    except ValueError:
        raise AcetError("ACET-IMP-005", f"source_class must be one of {[s.value for s in SourceClass]}") from None
    if corroboration not in CORROBORATION:
        raise AcetError("ACET-IMP-005", f"corroboration must be one of {CORROBORATION}")
    if not summary.strip():
        raise AcetError("ACET-IMP-005", "summary is required (ACET-EVT-001)")
    occurred, precision = (None, "UNKNOWN")
    if occurred_at:
        occurred, p = parse_external_timestamp(occurred_at)
        precision = p.value
    eid = uuid7()
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO external_event(id, product_id, event_type, occurred_at, time_precision, source_class,"
            " source_ref, summary, recorded_at, corroboration) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                eid,
                product_id,
                event_type,
                occurred,
                precision,
                sc.value,
                source_ref,
                summary,
                utc_now_iso(),
                corroboration,
            ),
        )
        repo.audit(tx, "event.add", "external_event", eid, {"source_class": sc.value})
    return eid


def _day(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return date.fromisoformat(s[:10]) if len(s) >= 10 else date.fromisoformat((s + "-01-01")[:10])
    except ValueError:
        return None


def correlated_events(
    ws: Workspace, product_id: str, start: str | None, end: str | None, margin_days: int = 7
) -> list[dict[str, Any]]:
    """Events within [start - margin, end + margin]. Each is labelled as a correlation only."""
    a, b = _day(start), _day(end)
    out = []
    for r in ws.db.conn.execute("SELECT * FROM external_event WHERE product_id=? ORDER BY occurred_at", (product_id,)):
        d = _day(r["occurred_at"])
        if d is None or a is None or b is None:
            continue
        if (a - d).days <= margin_days and (d - b).days <= margin_days:
            out.append(
                {
                    "event_id": r["id"],
                    "event_type": r["event_type"],
                    "occurred_at": r["occurred_at"],
                    "source_class": r["source_class"],
                    "summary": r["summary"],
                    "relation": CORRELATION_WORDING,
                    "evidence_strength": evidence_strength(r["source_class"], r["source_ref"], r["corroboration"]),
                    "causal_claim": False,
                }
            )
    return out
