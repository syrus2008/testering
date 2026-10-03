"""Content-addressed artifact store (ACET-STO-001..003, ACET-DATA-001, ACET-IMP-002/003).

Layout: ``artifacts/sha256/ab/cd/<sha256>`` (short internal paths, §62).

Writes go to ``temp/`` (same volume) and are moved into place with
``os.replace`` only after the copied bytes have been re-hashed and matched
against the source hash. Blobs are made read-only. A file left in ``temp/``
after a crash is never treated as valid output (ACC-095).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from acet.domain.error_codes import AcetError
from acet.domain.ids import is_sha256, require_sha256, uuid7

CHUNK = 1024 * 1024
DISK_MARGIN_BYTES = 64 * 1024 * 1024
TMP_SUFFIX = ".tmp"


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


@dataclass(frozen=True)
class PutResult:
    sha256: str
    size_bytes: int
    relpath: str
    created: bool  # False when the bytes were already present (ACET-IMP-003)


class ContentStore:
    def __init__(self, workspace_dir: Path) -> None:
        self.workspace_dir = Path(workspace_dir)
        self.root = self.workspace_dir / "artifacts"
        self.temp = self.workspace_dir / "temp"
        self.quarantine_dir = self.workspace_dir / "quarantine"
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    # -- paths ------------------------------------------------------------
    @staticmethod
    def relpath_for(sha: str) -> str:
        require_sha256(sha)
        return f"artifacts/sha256/{sha[:2]}/{sha[2:4]}/{sha}"

    def path_for(self, sha: str) -> Path:
        return self.workspace_dir / self.relpath_for(sha)

    def exists(self, sha: str) -> bool:
        return self.path_for(sha).is_file()

    def _lock_for(self, sha: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(sha, threading.Lock())

    # -- preflight --------------------------------------------------------
    def preflight(self, needed_bytes: int) -> None:
        self.temp.mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(self.temp).free
        if free < needed_bytes + DISK_MARGIN_BYTES:
            raise AcetError("ACET-IMP-003", data={"needed_bytes": needed_bytes, "free_bytes": free})

    # -- write ------------------------------------------------------------
    def put_file(self, source: Path, *, source_sha256: str | None = None) -> PutResult:
        """HASH → COPY → VERIFY → atomic rename. Never overwrites existing bytes."""
        try:
            src_sha, size = (source_sha256, source.stat().st_size) if source_sha256 else sha256_file(source)
        except OSError as exc:
            raise AcetError("ACET-IMP-001", type(exc).__name__) from exc
        assert src_sha is not None
        rel = self.relpath_for(src_sha)
        final = self.workspace_dir / rel

        with self._lock_for(src_sha):
            if final.is_file():
                return PutResult(src_sha, size, rel, created=False)
            self.preflight(size)
            tmp = self.temp / f"{uuid7()}{TMP_SUFFIX}"
            try:
                h = hashlib.sha256()
                copied = 0
                with open(source, "rb") as fin, open(tmp, "xb") as fout:
                    while chunk := fin.read(CHUNK):
                        fout.write(chunk)
                        h.update(chunk)
                        copied += len(chunk)
                    fout.flush()
                    os.fsync(fout.fileno())
                # ACET-IMP-002: re-hash what actually landed on disk.
                landed_sha, landed_size = sha256_file(tmp)
                if landed_sha != src_sha or h.hexdigest() != src_sha or landed_size != size:
                    raise AcetError("ACET-IMP-002", data={"expected": src_sha, "got": landed_sha})
                final.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(tmp, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
                os.replace(tmp, final)
            except AcetError:
                raise
            except FileNotFoundError as exc:
                raise AcetError("ACET-IMP-001", "source disappeared during import") from exc
            except OSError as exc:
                if exc.errno == 28:
                    raise AcetError("ACET-IMP-003", "ENOSPC during copy") from exc
                raise AcetError("ACET-IMP-001", type(exc).__name__) from exc
            finally:
                if tmp.exists():
                    _force_unlink(tmp)
            return PutResult(src_sha, size, rel, created=True)

    # -- verify -----------------------------------------------------------
    def verify(self, sha: str) -> bool:
        """True if the stored blob exists and still hashes to ``sha``."""
        p = self.path_for(sha)
        if not p.is_file():
            return False
        return sha256_file(p)[0] == sha

    # -- enumeration (reconcile) -----------------------------------------
    def iter_blobs(self) -> Iterator[tuple[str, Path]]:
        base = self.root / "sha256"
        if not base.is_dir():
            return
        for p in base.rglob("*"):
            if p.is_file():
                yield p.name, p

    def iter_temp_leftovers(self) -> Iterator[Path]:
        if self.temp.is_dir():
            yield from (p for p in self.temp.iterdir() if p.is_file() and p.name.endswith(TMP_SUFFIX))

    # -- quarantine (ACET-STO-003) ----------------------------------------
    def quarantine(self, path: Path, reason: str) -> Path:
        name = path.name if is_sha256(path.name) else f"{uuid7()}-{path.name}"
        dest = self.quarantine_dir / reason / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(path, dest)
        return dest


def _force_unlink(p: Path) -> None:
    try:
        os.chmod(p, stat.S_IREAD | stat.S_IWRITE)
        p.unlink()
    except OSError:
        pass
