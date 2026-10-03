"""Lineage Evidence Inspector and completeness banner (ADR-0012): the UI shows the report's wording —
a resurrection candidate is a hypothesis, a confirmation explains itself, a partial run says what is missing."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from acet.benchmark import scenarios
from acet.ui.app import MainWindow

DATA = Path(__file__).resolve().parents[2] / "datasets" / "resurrection"


@pytest.fixture
def corpus(monkeypatch):
    monkeypatch.setenv("ACET_GHIDRA_REPLAY_DIR", str(DATA / "golden" / "ghidra"))
    for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_BINDIFF", "ACET_QBINDIFF_PYTHON"):
        monkeypatch.delenv(k, raising=False)


def _window(qtbot, ws, scenario):
    out = scenarios.run_scenario(ws, DATA, scenario)
    path = ws.path
    ws.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    w.show()
    return w, out


def _idle(qtbot, w):
    qtbot.waitUntil(lambda: w.runner.active == 0, timeout=30_000)


def _inspect(qtbot, w, relation):
    w.goto("Lineage")
    _idle(qtbot, w)
    page = w.ctx.pages["Lineage"]
    table = page.table
    for r in range(table.proxy.rowCount()):
        if relation in (table.proxy.index(r, 3).data() or ""):
            table.view.setCurrentIndex(table.proxy.index(r, 0))
            break
    else:
        raise AssertionError(f"no lineage with {relation}")
    _idle(qtbot, w)
    hist = page.hist
    for r in range(hist.proxy.rowCount()):
        if hist.proxy.index(r, 1).data() == relation:
            hist.view.setCurrentIndex(hist.proxy.index(r, 0))
            return page, hist.proxy.index(r, 2).data(), hist.proxy.index(r, 3).data()
    raise AssertionError(f"no history row {relation}")


def test_candidate_is_inspected_as_a_hypothesis(qtbot, ws, corpus):
    w, _ = _window(qtbot, ws, "recompiled_heavy")
    page, inference, statement = _inspect(qtbot, w, "RESURRECTED_CANDIDATE")
    assert inference == "HYPOTHESIS" and "hypothesis" in statement.lower()
    text = page.inspector.toPlainText()
    assert text.startswith("⚠ HYPOTHESIS — NOT ESTABLISHED")
    assert "NOT reused" in text and "Supporting families:    context, data" in text
    assert "lineage_run_id" in text and "resurrect@2" in text
    w.runner.wait(30_000)


def test_confirmed_resurrection_explains_the_reused_identity(qtbot, ws, corpus):
    w, _ = _window(qtbot, ws, "identical")
    page, inference, _ = _inspect(qtbot, w, "RESURRECTED_CONFIRMED")
    text = page.inspector.toPlainText()
    assert inference == "CONFIRMED_BY_RULE" and "HYPOTHESIS" not in text
    assert "Historical identity reused because independent evidence converges" in text
    w.runner.wait(30_000)


def test_partial_run_banner_on_compare_and_changes(qtbot, ws, corpus):
    w, _out = _window(qtbot, ws, "identical")  # replay: ghidriff unavailable → COMPLETED_PARTIAL
    w.goto("Compare")
    _idle(qtbot, w)
    page = w.ctx.pages["Compare"]
    page.runs.setCurrentIndex(0)
    _idle(qtbot, w)
    assert page.banner.isVisible()
    text = page.banner.text()
    assert "PARTIAL RESULT" in text and "ghidriff" in text and "not negative evidence" in text
    w.goto("Changes")
    _idle(qtbot, w)
    changes = w.ctx.pages["Changes"]
    _idle(qtbot, w)
    assert changes.banner.isVisible() and "not negative evidence" in changes.banner.text()
    w.runner.wait(30_000)
