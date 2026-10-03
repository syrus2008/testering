"""DISCOVER stage (ACET-FS-001, ACC-065).

Paths are canonicalized; symlinks/junctions are resolved, loops detected via
(device, inode) of visited directories and a maximum depth. Discovery returns
regular files only, de-duplicated by resolved path.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from acet.domain.error_codes import AcetError

MAX_DEPTH = 32
MAX_FILES = 100_000


@dataclass
class Discovery:
    files: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def discover(paths: Iterable[Path], *, max_depth: int = MAX_DEPTH, max_files: int = MAX_FILES) -> Discovery:
    out = Discovery()
    seen_files: set[Path] = set()
    seen_dirs: set[tuple[int, int]] = set()

    def add_file(p: Path) -> None:
        if p in seen_files:
            return
        if len(seen_files) >= max_files:
            raise AcetError("ACET-IMP-005", f"more than {max_files} files")
        seen_files.add(p)
        out.files.append(p)

    def walk(d: Path, depth: int) -> None:
        if depth > max_depth:
            out.warnings.append(f"max depth {max_depth} reached; deeper entries ignored")
            return
        st = d.stat()
        key = (st.st_dev, st.st_ino)
        if key in seen_dirs:
            out.warnings.append("directory loop (symlink/junction) detected and skipped")
            return
        seen_dirs.add(key)
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError as exc:
            out.warnings.append(f"unreadable directory skipped ({type(exc).__name__})")
            return
        for entry in entries:
            try:
                resolved = Path(entry.path).resolve(strict=True)
            except (OSError, RuntimeError):
                out.warnings.append("broken or looping link skipped")
                continue
            if resolved.is_dir():
                walk(resolved, depth + 1)
            elif resolved.is_file():
                add_file(resolved)

    for raw in paths:
        try:
            p = Path(raw).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AcetError("ACET-IMP-001", f"{type(exc).__name__}: {Path(raw).name}") from exc
        if p.is_dir():
            walk(p, 0)
        elif p.is_file():
            add_file(p)
        else:
            raise AcetError("ACET-IMP-005", f"not a regular file or directory: {p.name}")
    return out
