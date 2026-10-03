"""Workspace capacity classes (spec §107, ACET-CAP-001, ACC-121)."""

from __future__ import annotations

from typing import Any

from acet.application.workspace import Workspace

CLASSES = (("S", 25, 50_000), ("M", 250, 1_000_000), ("L", 2_500, 10_000_000))
VALIDATED = ("S", "M")


def capacity(ws: Workspace) -> dict[str, Any]:
    builds = ws.db.conn.execute("SELECT count(*) FROM build WHERE deleted_at IS NULL").fetchone()[0]
    functions = ws.db.conn.execute("SELECT count(*) FROM function_instance").fetchone()[0]
    return classify(builds, functions)


def classify(builds: int, functions: int) -> dict[str, Any]:
    cls = next((name for name, b, f in CLASSES if builds <= b and functions <= f), "XL")
    validated = cls in VALIDATED
    return {
        "class": cls,
        "builds": builds,
        "function_instances": functions,
        "validated": validated,
        "warning": None
        if validated
        else f"Workspace is in capacity class {cls}, outside the validated envelope {VALIDATED}: published SLOs do "
        "not apply (OUTSIDE_VALIDATED_CAPACITY).",
    }
