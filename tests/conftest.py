from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from acet.application.products import create_product
from acet.application.workspace import Workspace, create_workspace

# A fictitious product: the Core must not depend on any real anti-cheat (ACC-041).
FICT_PROFILE = {
    "schema_version": 2,
    "product_name": "Fictional Guard",
    "expected_roles": ["KERNEL_DRIVER", "EXECUTABLE", "USER_MODULE"],
    "optional_roles": ["CONFIGURATION"],
    "filename_hints": ["Fict*.sys"],
}


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACET_HOME", str(tmp_path / "acet-home"))
    monkeypatch.delenv("ACET_WORKSPACE", raising=False)


@pytest.fixture(autouse=True)
def _no_real_distribution(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never reach the real Engine Pack distribution of this build (tests/live opts in)."""
    if request.node.get_closest_marker("real_distribution") is None:
        from acet.platform import engine_manager

        monkeypatch.setattr(engine_manager, "_bundled_distribution", lambda: {"channel": "test", "index_urls": []})
        monkeypatch.delenv("ACET_ENGINE_INDEX_URL", raising=False)


@pytest.fixture
def ws(tmp_path: Path) -> Iterator[Workspace]:
    w = create_workspace("test", tmp_path / "workspaces")
    try:
        yield w
    finally:
        w.close()


@pytest.fixture
def product_id(ws: Workspace) -> str:
    return create_product(ws, "Fictional Guard", vendor="Nobody", profile=FICT_PROFILE)
