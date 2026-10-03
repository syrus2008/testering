"""Path / identity minimisation for logs, diagnostics and exports (ACET-PRI-001/002, ACC-032/076)."""

from __future__ import annotations

import getpass
import os
import re
from pathlib import Path

_PDB = re.compile(r"(?i)(?:[a-z]:)?[\\/][^\s\"'<>|]*?\.pdb")
_WINPATH = re.compile(r"(?i)\b[a-z]:\\(?:[^\\\s\"'<>|]+\\)*[^\\\s\"'<>|]*")
_POSIXHOME = re.compile(r"/(?:home|Users)/[^/\s\"']+")


def sanitize(text: str, *, workspace: Path | None = None) -> str:
    out = text
    if workspace is not None:
        out = out.replace(str(workspace), "<WORKSPACE>")
    home = str(Path.home())
    if home and home not in ("/", ""):
        out = out.replace(home, "<HOME>")
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    out = _PDB.sub("<PDB-PATH>", out)
    out = _WINPATH.sub("<PATH>", out)
    out = _POSIXHOME.sub("<HOME>", out)
    if user and len(user) > 2:
        out = re.sub(rf"(?i)\b{re.escape(user)}\b", "<USER>", out)
    return out
