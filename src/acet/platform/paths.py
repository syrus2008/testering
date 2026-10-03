"""Disk layout (spec §8)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

WORKSPACE_SUBDIRS = (
    "artifacts",
    "derived",
    "reports",
    "exports",
    "backups",
    "logs",
    "temp",
    "quarantine",
)
DB_FILENAME = "acet.db"


def acet_home() -> Path:
    """%LOCALAPPDATA%\\ACET on Windows; XDG data dir elsewhere (development only).

    ``ACET_HOME`` overrides for tests and portable installs.
    """
    override = os.environ.get("ACET_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "ACET"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "acet"


def workspaces_root() -> Path:
    return acet_home() / "workspaces"
