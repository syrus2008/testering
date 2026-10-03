"""ACET-TRACE-001/002: the committed acceptance matrix must match the tests."""

from __future__ import annotations

from tools.gen_traceability import OUT, build, render


def test_acceptance_matrix_is_up_to_date():
    assert OUT.read_text(encoding="utf-8") == render(), "run: python tools/gen_traceability.py"


def test_matrix_covers_all_150_criteria():
    rows = build()["criteria"]
    assert [r["id"] for r in rows][:150] == [f"ACC-{n:03d}" for n in range(1, 151)]
    assert [r["id"] for r in rows][150:] == [f"ACC-ENGINE-{n:03d}" for n in range(1, 7)]
    assert all(r["subject"] and r["criterion"] for r in rows)
