"""Local version watch: notice when watched binaries change and import each new version as a build.

A *watch source* names a product and one or more local folders or files (for example the folders where an
anti-cheat installs itself). A scan hashes the executables found there (PE files: .sys, .exe, .dll, ...); when the
set differs from the last one seen, the files are copied to a snapshot, the copy is re-hashed against the source
(a version being written by an updater is never captured half-way), and the snapshot is imported as a new build,
observed now. Nothing is executed; sources are only read. Unreadable files (locked, access denied) make the scan
``LOCKED`` and nothing is imported: the next scan retries.

Fully automatic by default (Watch page): discovery of known install locations (``watch_presets.json``, data only:
the Core knows no product), a check at start-up and every N minutes, a plain-file copy of each version under
``Documents/ACET Versions`` (with a manifest), import, and comparison with the previous version when the engines
are ready. State lives in ``<workspace>/watch.json`` (sources, options, history), written atomically.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.error_codes import AcetError
from acet.domain.timeutil import utc_now_iso

STATE_FILE = "watch.json"
PE_SUFFIXES = {".sys", ".exe", ".dll", ".ocx", ".cpl", ".scr", ".efi", ".drv"}
MAX_FILES = 500
MAX_FILE_BYTES = 512 * 1024**2
MAX_DEPTH = 4


# Fully automatic by default: find the installations, check at start-up and every 30 minutes, keep a copy of each
# version, import it and compare it with the previous one. Every option can be switched off on the Watch page.
DEFAULTS: dict[str, Any] = {
    "interval_minutes": 30,
    "auto": True,
    "auto_discover": True,
    "auto_compare": True,
    "archive_dir": None,  # None: default_archive_dir()
    "ignored_paths": [],  # auto-discovered locations the user removed: never re-added
}


def default_archive_dir() -> Path:
    """Where each captured version is kept as plain files (outside the workspace, easy to browse)."""
    override = os.environ.get("ACET_WATCH_ARCHIVE")
    return Path(override) if override else Path.home() / "Documents" / "ACET Versions"


def archive_dir(ws: Workspace) -> Path:
    v = load_state(ws).get("archive_dir")
    return Path(v) if v else default_archive_dir()


def set_option(ws: Workspace, key: str, value: Any) -> None:
    if key not in ("auto", "auto_discover", "auto_compare", "archive_dir"):
        raise AcetError("ACET-WATCH-001", f"unknown watch option {key}")
    state = load_state(ws)
    state[key] = (str(value) if value else None) if key == "archive_dir" else bool(value)
    _save_state(ws, state)


@dataclass
class WatchSource:
    id: str
    label: str
    product: str
    paths: list[str]
    enabled: bool = True
    auto: bool = False  # added by automatic discovery
    last_fingerprint: str | None = None
    last_build_id: str | None = None
    last_checked_at: str | None = None
    last_changed_at: str | None = None
    last_status: str | None = None
    last_detail: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanResult:
    source_id: str
    label: str
    status: str  # NEW_VERSION | UNCHANGED | LOCKED | UNSTABLE | EMPTY | ERROR | DISABLED
    detail: str = ""
    build_id: str | None = None
    created_build: bool = False
    previous_build_id: str | None = None  # the version before this one (for the automatic comparison)
    archive_path: str | None = None
    product: str = ""
    files: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ------------------------------------------------------------------ state
def _state_path(ws: Workspace) -> Path:
    return ws.path / STATE_FILE


def load_state(ws: Workspace) -> dict[str, Any]:
    p = _state_path(ws)
    if not p.is_file():
        return {"version": 1, "sources": [], **DEFAULTS}
    data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
    for k, v in DEFAULTS.items():
        data.setdefault(k, v)
    data.setdefault("sources", [])
    return data


def _save_state(ws: Workspace, state: dict[str, Any]) -> None:
    ws.require_writable()
    p = _state_path(ws)
    tmp = p.with_name(f"{p.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)


def list_sources(ws: Workspace) -> list[WatchSource]:
    fields = WatchSource.__dataclass_fields__
    return [WatchSource(**{k: v for k, v in s.items() if k in fields}) for s in load_state(ws)["sources"]]


def _put(ws: Workspace, src: WatchSource) -> None:
    state = load_state(ws)
    state["sources"] = [s for s in state["sources"] if s["id"] != src.id] + [asdict(src)]
    state["sources"].sort(key=lambda s: s["label"].lower())
    _save_state(ws, state)


def set_interval(ws: Workspace, minutes: int) -> None:
    if not 5 <= minutes <= 24 * 60:
        raise AcetError("ACET-WATCH-001", "watch interval must be between 5 minutes and 24 hours")
    state = load_state(ws)
    state["interval_minutes"] = int(minutes)
    _save_state(ws, state)


def set_auto(ws: Workspace, enabled: bool) -> None:
    """Scan automatically every ``interval_minutes`` while ACET is open."""
    state = load_state(ws)
    state["auto"] = bool(enabled)
    _save_state(ws, state)


def last_two_builds(src: WatchSource) -> tuple[str, str] | None:
    """The two most recent distinct versions seen for a source (older, newer)."""
    ids: list[str] = []
    for h in reversed(src.history):
        if h["build_id"] not in ids:
            ids.append(h["build_id"])
        if len(ids) == 2:
            return ids[1], ids[0]
    return None


def add_source(ws: Workspace, label: str, product: str, paths: list[str], *, auto: bool = False) -> WatchSource:
    """Watch ``paths`` for ``product`` (created if it does not exist yet)."""
    from acet.application.products import create_product
    from acet.storage import repositories as repo

    clean = [str(Path(p)) for p in paths if str(p).strip()]
    if not clean:
        raise AcetError("ACET-WATCH-001", "a watch source needs at least one folder or file")
    missing = [p for p in clean if not Path(p).exists()]
    if len(missing) == len(clean):
        raise AcetError("ACET-WATCH-001", f"none of the paths exists: {missing}")
    if repo.find_product(ws.db.conn, product) is None:
        create_product(ws, product)
    for s in list_sources(ws):
        if s.product == product and sorted(s.paths) == sorted(clean):
            return s  # already watched
    src = WatchSource(id=uuid.uuid4().hex[:12], label=label.strip() or product, product=product, paths=clean, auto=auto)
    _put(ws, src)
    return src


def remove_source(ws: Workspace, source_id: str) -> None:
    state = load_state(ws)
    gone = [s for s in state["sources"] if s["id"] == source_id]
    if not gone:
        raise AcetError("ACET-NOTFOUND-001", f"watch source {source_id}")
    state["sources"] = [s for s in state["sources"] if s["id"] != source_id]
    if gone[0].get("auto"):  # removed by the user: automatic discovery must not bring it back
        state["ignored_paths"] = sorted({*state.get("ignored_paths", []), *(p.lower() for p in gone[0]["paths"])})
    _save_state(ws, state)


def set_enabled(ws: Workspace, source_id: str, enabled: bool) -> None:
    src = _get(ws, source_id)
    src.enabled = enabled
    _put(ws, src)


def _get(ws: Workspace, source_id: str) -> WatchSource:
    for s in list_sources(ws):
        if s.id == source_id:
            return s
    raise AcetError("ACET-NOTFOUND-001", f"watch source {source_id}")


# ------------------------------------------------------------------ files
def _is_pe(p: Path) -> bool:
    if p.suffix.lower() not in PE_SUFFIXES:
        return False
    try:
        with open(p, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return True  # unreadable: kept so that the scan reports it as locked instead of silently skipping it


def _walk(root: Path, depth: int = 0) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    try:
        entries = sorted(root.iterdir(), key=lambda e: e.name.lower())
    except OSError:
        return out
    for e in entries:
        if e.is_symlink():
            continue
        if e.is_dir() and depth < MAX_DEPTH:
            out += _walk(e, depth + 1)
        elif e.is_file():
            out.append(e)
    return out


def collect_files(paths: list[str]) -> list[tuple[str, Path]]:
    """(relative name, path) of the executables under the watched paths, in a stable order."""
    files: list[tuple[str, Path]] = []
    for raw in paths:
        root = Path(raw)
        if not root.exists():
            continue
        prefix = root.name if root.is_dir() else ""
        for f in _walk(root):
            if not _is_pe(f):
                continue
            rel = f.name if root.is_file() else f"{prefix}/{f.relative_to(root).as_posix()}"
            files.append((rel, f))
            if len(files) > MAX_FILES:
                raise AcetError("ACET-WATCH-001", f"more than {MAX_FILES} executables under the watched paths")
    return sorted(files, key=lambda t: t[0].lower())


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def fingerprint(entries: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        "\n".join(
            f"{e['name'].lower()}\t{e['sha256']}" for e in sorted(entries, key=lambda e: e["name"].lower())
        ).encode()
    ).hexdigest()


# ------------------------------------------------------------------ scan
def scan_source(ws: Workspace, source_id: str) -> ScanResult:
    from acet.domain.enums import ObservationSourceType
    from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build

    src = _get(ws, source_id)
    now = utc_now_iso()
    res = ScanResult(src.id, src.label, "UNCHANGED", product=src.product)
    if not src.enabled:
        res.status = "DISABLED"
        return res
    try:
        files = collect_files(src.paths)
        entries: list[dict[str, Any]] = []
        for rel, p in files:
            try:
                size = p.stat().st_size
                if size > MAX_FILE_BYTES:
                    continue
                entries.append({"name": rel, "sha256": _sha256(p), "size": size, "path": p})
            except OSError as exc:
                res.status, res.detail = "LOCKED", f"{rel}: {exc.strerror or exc}"
                break
        if res.status == "LOCKED":
            pass
        elif not entries:
            res.status, res.detail = "EMPTY", "no executable found in the watched paths"
        else:
            fp = fingerprint(entries)
            res.files = [{k: e[k] for k in ("name", "sha256", "size")} for e in entries]
            if fp != src.last_fingerprint:
                _capture(ws, src, entries, fp, res, now, ImportRequest, import_build, DuplicatePolicy,
                         ObservationSourceType)  # fmt: skip
    except AcetError as exc:
        res.status, res.detail = "ERROR", f"{exc.code}: {exc.detail}"
    src.last_checked_at, src.last_status, src.last_detail = now, res.status, res.detail
    _put(ws, src)
    return res


def _capture(ws: Workspace, src: WatchSource, entries: list[dict[str, Any]], fp: str, res: ScanResult, now: str,
             ImportRequest: Any, import_build: Any, DuplicatePolicy: Any, ObservationSourceType: Any) -> None:  # fmt: skip
    """Copy, re-verify against the source, import, then drop the snapshot (the build store keeps the bytes)."""
    snap = ws.path / "watch" / "snapshots" / f"{src.id}-{uuid.uuid4().hex[:8]}"
    try:
        for e in entries:
            dest = snap / e["name"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(e["path"], dest)
            except OSError as exc:
                res.status, res.detail = "LOCKED", f"{e['name']}: {exc.strerror or exc}"
                return
            if _sha256(dest) != e["sha256"] or _sha256(e["path"]) != e["sha256"]:
                res.status, res.detail = "UNSTABLE", f"{e['name']} changed while being copied (update in progress?)"
                return
        label = f"{src.label} {now[:16].replace('T', ' ')}"
        r = import_build(
            ws,
            ImportRequest(
                [snap],
                src.product,
                release_label=label,
                observed_at=now,
                source_type=ObservationSourceType.OTHER,
                source_label=f"watch:{src.label}"[:80],
                on_duplicate=DuplicatePolicy.ADD_OBSERVATION,
            ),
        )
        res.status, res.build_id, res.created_build = "NEW_VERSION", r.build_id, r.created_build
        res.previous_build_id = src.last_build_id if src.last_build_id != r.build_id else None
        res.detail = f"{len(entries)} file(s)" + ("" if r.created_build else "; same as an earlier build (re-observed)")
        if r.created_build:
            res.archive_path = str(_archive(ws, src, snap, entries, now, label, r.build_id))
        src.last_fingerprint, src.last_build_id, src.last_changed_at = fp, r.build_id, now
        src.history.append({"at": now, "build_id": r.build_id, "release": label, "files": len(entries),
                            "new_build": r.created_build, "fingerprint": fp,
                            "archive_path": res.archive_path})  # fmt: skip
        src.history = src.history[-200:]
    finally:
        shutil.rmtree(snap, ignore_errors=True)
        with contextlib.suppress(OSError):
            (ws.path / "watch" / "snapshots").rmdir()


def _safe(name: str) -> str:
    return "".join("_" if c in '<>:"/\\|?*' or ord(c) < 32 else c for c in name).strip(" .") or "_"


def _archive(ws: Workspace, src: WatchSource, snap: Path, entries: list[dict[str, Any]], now: str, label: str,
             build_id: str) -> Path:  # fmt: skip
    """Keep this version as plain files: <archive>/<product>/<date time> <source>/ + manifest.json."""
    base = archive_dir(ws) / _safe(src.product) / _safe(f"{now[:19].replace('T', ' ').replace(':', '')} {src.label}")
    base.parent.mkdir(parents=True, exist_ok=True)
    dest, n = base, 1
    while dest.exists():  # never mix two versions in one folder
        n += 1
        dest = base.with_name(f"{base.name} ({n})")
    shutil.copytree(snap, dest)
    manifest = {"product": src.product, "source": src.label, "watched_paths": src.paths, "captured_at": now,
                "build_id": build_id, "build_label": label,
                "files": [{k: e[k] for k in ("name", "sha256", "size")} for e in entries]}  # fmt: skip
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return dest


def scan_all(ws: Workspace) -> list[ScanResult]:
    return [scan_source(ws, s.id) for s in list_sources(ws) if s.enabled]


def auto_discover(ws: Workspace) -> list[WatchSource]:
    """Watch every detected installation not watched yet (unless the user removed it before)."""
    state = load_state(ws)
    known = {p.lower() for s in state["sources"] for p in s["paths"]} | set(state.get("ignored_paths", []))
    added = []
    for c in detect_candidates():
        if any(p.lower() in known for p in c["paths"]):
            continue
        added.append(add_source(ws, c["label"], c["product"], c["paths"], auto=True))
        known |= {p.lower() for p in c["paths"]}
    return added


def compare_new_versions(ws: Workspace, results: list[ScanResult]) -> list[str]:
    """Compare each newly captured version with the previous one (STANDARD) when the engines allow it."""
    from acet.analysis.orchestrator import compare_builds
    from acet.platform import engine_manager as em

    if not load_state(ws)["auto_compare"]:
        return []
    out = []
    for r in results:
        if r.status != "NEW_VERSION" or not r.created_build or not r.previous_build_id or not r.build_id:
            continue
        if em.profile_gate("STANDARD@1")["state"] not in ("READY", "DEGRADED"):
            out.append(f"{r.label}: install the Engine Pack to compare automatically")
            continue
        try:
            summary = compare_builds(ws, r.previous_build_id, r.build_id, "STANDARD@1")
            out.append(f"{r.label} compared with the previous version ({summary.status}) — see Changes")
        except Exception as exc:  # the version is captured; a failed comparison is reported, never fatal
            out.append(f"{r.label}: comparison failed ({exc})")
    return out


def run_cycle(ws: Workspace, *, compare: bool = True) -> dict[str, Any]:
    """One automatic round: discover (if enabled), check every enabled source, compare new versions."""
    added = auto_discover(ws) if load_state(ws)["auto_discover"] else []
    results = scan_all(ws)
    return {"added": [s.label for s in added], "results": results,
            "compared": compare_new_versions(ws, results) if compare else []}  # fmt: skip


# ------------------------------------------------------------------ Windows: also while ACET is closed
def scheduled_task_command(ws: Workspace, minutes: int) -> list[str]:
    from acet.jobs.winschedule import task_command

    return task_command(["watch", "cycle", "-w", str(ws.path)], minutes)


def set_background_task(ws: Workspace, enabled: bool) -> str:
    """Register or remove the Windows scheduled task running ``acet watch cycle`` (current user, no elevation)."""
    from acet.jobs import winschedule

    out = (
        winschedule.register(scheduled_task_command(ws, int(load_state(ws)["interval_minutes"])))
        if enabled
        else (winschedule.unregister())
    )
    state = load_state(ws)
    state["background_task"] = bool(enabled)
    _save_state(ws, state)
    return out


# ------------------------------------------------------------------ discovery
def _presets() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (resources.files("acet.application") / "watch_presets.json").read_text(encoding="utf-8")
    )
    return data


def _expand(path: str) -> Path | None:
    """Expand Windows-style %VAR% (case-insensitive, on every OS); None when a variable is not set."""
    env = {k.upper(): v for k, v in os.environ.items()}
    missing = False

    def sub(m: re.Match[str]) -> str:
        nonlocal missing
        val = env.get(m.group(1).upper())
        missing = missing or val is None
        return val or ""

    out = re.sub(r"%([^%]+)%", sub, path)
    return None if missing else Path(out.replace("\\", os.sep) if os.sep != "\\" else out)


def steam_libraries() -> list[Path]:
    """Steam library folders (steamapps/common) from libraryfolders.vdf; read-only, best effort."""
    roots: list[Path] = []
    for base in (_expand(r"%ProgramFiles(x86)%\Steam"), _expand(r"%ProgramFiles%\Steam"),
                 Path.home() / ".steam" / "steam", Path.home() / ".local" / "share" / "Steam"):  # fmt: skip
        if base is None:
            continue
        vdf = base / "steamapps" / "libraryfolders.vdf"
        cands = [base]
        if vdf.is_file():
            with contextlib.suppress(OSError):
                for line in vdf.read_text(encoding="utf-8", errors="replace").splitlines():
                    parts = line.strip().split('"')
                    if len(parts) >= 4 and parts[1] == "path":
                        cands.append(Path(parts[3].replace("\\\\", "\\")))
        for c in cands:
            common = c / "steamapps" / "common"
            if common.is_dir() and common not in roots:
                roots.append(common)
    return roots


def detect_candidates(extra_game_roots: list[Path] | None = None) -> list[dict[str, Any]]:
    """Folders that look like a known product's install location, as suggestions (never added automatically)."""
    p = _presets()
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(product: str, label: str, path: Path) -> None:
        key = str(path).lower()
        if key in seen or not collect_files([str(path)]):
            return
        seen.add(key)
        out.append({"product": product, "label": label, "paths": [str(path)]})

    for prod in p["products"]:
        for loc in prod.get("system_locations", []):
            d = _expand(loc)
            if d is not None and d.is_dir():
                add(prod["product"], f"{prod['product']} (system)", d)
    roots = steam_libraries() + list(extra_game_roots or [])
    for common in roots:
        try:
            games = [g for g in common.iterdir() if g.is_dir()]
        except OSError:
            continue
        for game in games:
            for prod in p["products"]:
                for sub in prod.get("game_subfolders", []):
                    for d in (game / sub, *(game / x / sub for x in ("Binaries", "Game", "bin"))):
                        if d.is_dir():
                            add(prod["product"], f"{game.name} — {prod['product']}", d)
    return out
