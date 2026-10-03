"""Path / identity minimisation for logs, diagnostics and exports (ACET-PRI-001/002, ACC-032/076)."""

from __future__ import annotations

import getpass
import os
import re
from pathlib import Path
from typing import Any

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


def sanitize_obj(obj: Any, *, workspace: Path | None = None) -> Any:
    """``sanitize`` applied to every string of a JSON-like value *before* serialisation: rewriting the JSON text
    instead would cut Windows paths in the middle of their escaped backslashes and produce invalid JSON."""
    if isinstance(obj, str):
        return sanitize(obj, workspace=workspace)
    if isinstance(obj, dict):
        return {sanitize(str(k), workspace=workspace): sanitize_obj(v, workspace=workspace) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [sanitize_obj(v, workspace=workspace) for v in obj]
    return obj
