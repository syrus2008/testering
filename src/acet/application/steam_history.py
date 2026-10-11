"""Dated older versions of an anti-cheat, fetched through the Steam client the user is already signed in to.

A game installed with Steam ships its anti-cheat folder (a folder named in ``watch_presets.json``) inside its
depot; every published version of that depot is a *manifest* with a date (listed on SteamDB). The Steam client's
own console command ``download_depot <app> <depot> <manifest>`` downloads that exact version with the account
already signed in on this PC: ACET never sees, asks for or stores a password or token.

Flow (the Watch page drives it):

1. :func:`installed_games` reads the Steam libraries (``appmanifest_*.acf``, read-only) and keeps the games that
   contain an anti-cheat folder known to ``watch_presets.json``; their depots and current manifest come from there.
2. The user pastes the manifest list of the depot copied from SteamDB; :func:`parse_manifest_list` extracts the
   manifest ids and their dates (nothing is scraped).
3. For each chosen version, :func:`begin` clears Steam's scratch folder for that depot and gives the console
   command; the Watch page copies it and opens the Steam console. :func:`poll` follows Steam's console log until
   "Depot download complete" (or a failure) for that depot.
4. :func:`capture` copies only the executables of the anti-cheat folders (copy re-verified), imports them as a build
   observed at the manifest date, keeps them in the versions folder with a manifest.json, compares them with the
   version currently installed, then deletes the full depot download (Steam's scratch folder, often large).

Downloaded files are only read, never executed. State lives in ``<workspace>/steam_history.json``.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from acet.application import watch
from acet.application.workspace import Workspace
from acet.domain.error_codes import AcetError
from acet.domain.timeutil import utc_now_iso

STATE_FILE = "steam_history.json"
STEAMID64_BASE = 76561197960265728


# ------------------------------------------------------------------ Valve KeyValues (text VDF / ACF)
def parse_vdf(text: str) -> dict[str, Any]:
    """Minimal reader for Valve's text KeyValues (``"key" "value"`` and ``"key" { ... }``); keys keep their case."""
    tokens = re.findall(r'"((?:[^"\\]|\\.)*)"|([{}])', text)
    root: dict[str, Any] = {}
    stack = [root]
    key: str | None = None
    for quoted, brace in tokens:
        if brace == "{":
            child: dict[str, Any] = {}
            if key is not None:
                stack[-1][key] = child
            stack.append(child)
            key = None
        elif brace == "}":
            if len(stack) > 1:
                stack.pop()
            key = None
        else:
            value = quoted.replace("\\\\", "\\").replace('\\"', '"')
            if key is None:
                key = value
            else:
                stack[-1][key] = value
                key = None
    return root


def _get_ci(d: dict[str, Any], key: str) -> Any:
    """Case-insensitive lookup (Valve files mix ``AppState``/``appstate``)."""
    for k, v in d.items():
        if k.lower() == key.lower():
            return v
    return None


# ------------------------------------------------------------------ the local Steam client
def steam_root() -> Path | None:
    """The Steam client folder: ``ACET_STEAM_ROOT``, the registry (Windows), then the usual locations."""
    override = os.environ.get("ACET_STEAM_ROOT")
    if override:
        return Path(override) if (Path(override) / "steamapps").is_dir() else None
    if sys.platform == "win32":
        with contextlib.suppress(OSError, ImportError):
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as k:
                p = Path(str(winreg.QueryValueEx(k, "SteamPath")[0]))
                if p.is_dir():
                    return p
    for base in (
        watch._expand(r"%ProgramFiles(x86)%\Steam"),
        watch._expand(r"%ProgramFiles%\Steam"),
        Path.home() / ".steam" / "steam",
        Path.home() / ".local" / "share" / "Steam",
    ):
        if base is not None and (base / "steamapps").is_dir():
            return base
    return None


def _active_account_id() -> int | None:
    """Account id of the user signed in to the running Steam client (Windows registry), else None."""
    if sys.platform != "win32" or os.environ.get("ACET_STEAM_ROOT"):
        return None
    with contextlib.suppress(OSError, ImportError):
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam\ActiveProcess") as k:
            return int(winreg.QueryValueEx(k, "ActiveUser")[0]) or None
    return None


def signed_in_account(root: Path | None = None) -> dict[str, Any]:
    """Who is signed in to Steam on this PC (names only, from ``config/loginusers.vdf``; never a credential).

    ``running`` is True when the registry shows a signed-in running client (Windows), None when unknown."""
    root = root or steam_root()
    if root is None:
        raise AcetError("ACET-STEAM-001", "Steam is not installed on this PC (no Steam folder found)")
    users: dict[str, Any] = {}
    with contextlib.suppress(OSError):
        users = (
            _get_ci(
                parse_vdf((root / "config" / "loginusers.vdf").read_text(encoding="utf-8", errors="replace")), "users"
            )
            or {}
        )
    active = _active_account_id()
    chosen: tuple[str, dict[str, Any]] | None = None
    for sid, info in users.items():
        if not isinstance(info, dict):
            continue
        with contextlib.suppress(ValueError):
            if active is not None and int(sid) - STEAMID64_BASE == active:
                chosen = (sid, info)
                break
        if chosen is None or str(_get_ci(info, "MostRecent")) == "1":
            chosen = (sid, info)
    if sys.platform == "win32" and not os.environ.get("ACET_STEAM_ROOT"):
        running: bool | None = active is not None
    else:
        running = None
    if chosen is None:
        return {"root": str(root), "account": None, "persona": None, "running": running}
    return {
        "root": str(root),
        "account": _get_ci(chosen[1], "AccountName"),
        "persona": _get_ci(chosen[1], "PersonaName"),
        "running": running,
    }


def library_folders(root: Path) -> list[Path]:
    """Every Steam library (folders containing ``steamapps``), the client's own first."""
    out = [root]
    with contextlib.suppress(OSError):
        data = parse_vdf((root / "steamapps" / "libraryfolders.vdf").read_text(encoding="utf-8", errors="replace"))
        for v in (_get_ci(data, "libraryfolders") or {}).values():
            p = _get_ci(v, "path") if isinstance(v, dict) else v
            if isinstance(p, str) and p and Path(p) not in out:
                out.append(Path(p))
    return [p for p in out if (p / "steamapps").is_dir()]


def _ac_folders(game_dir: Path) -> list[tuple[str, Path]]:
    """(product, folder) for each anti-cheat folder known to the presets found in a game (or depot) folder."""
    found: list[tuple[str, Path]] = []
    for prod in watch._presets()["products"]:
        for sub in prod.get("game_subfolders", []):
            for d in (game_dir / sub, *(game_dir / x / sub for x in ("Binaries", "Game", "bin"))):
                if d.is_dir() and watch.collect_files([str(d)]):
                    found.append((prod["product"], d))
    return found


def installed_games(root: Path | None = None) -> list[dict[str, Any]]:
    """Installed Steam games that contain a known anti-cheat folder, with their depots (read-only)."""
    root = root or steam_root()
    if root is None:
        raise AcetError("ACET-STEAM-001", "Steam is not installed on this PC (no Steam folder found)")
    games: list[dict[str, Any]] = []
    for lib in library_folders(root):
        for acf in sorted((lib / "steamapps").glob("appmanifest_*.acf")):
            try:
                st = _get_ci(parse_vdf(acf.read_text(encoding="utf-8", errors="replace")), "AppState") or {}
            except OSError:
                continue
            appid, name, installdir = (str(_get_ci(st, k) or "") for k in ("appid", "name", "installdir"))
            if not appid or not installdir:
                continue
            game_dir = lib / "steamapps" / "common" / installdir
            ac = _ac_folders(game_dir)
            if not ac:
                continue
            depots: list[dict[str, Any]] = []
            for depot_id, info in (_get_ci(st, "InstalledDepots") or {}).items():
                if isinstance(info, dict):
                    depots.append(
                        {
                            "depot": str(depot_id),
                            "manifest": str(_get_ci(info, "manifest") or ""),
                            "size": int(_get_ci(info, "size") or 0),
                        }
                    )
            depots.sort(key=lambda d: -int(d["size"]))  # the anti-cheat folder is usually in the main (largest) depot
            games.append(
                {
                    "appid": appid,
                    "name": name or installdir,
                    "dir": str(game_dir),
                    "depots": depots,
                    "products": sorted({p for p, _ in ac}),
                    "anticheat_dirs": [str(d) for _, d in ac],
                }
            )
    return games


def steamdb_url(depot: str) -> str:
    return f"https://steamdb.info/depot/{depot}/manifests/"


# ------------------------------------------------------------------ the pasted SteamDB list
_MONTHS = {
    m: i
    for i, m in enumerate(
        [
            "january",
            "february",
            "march",
            "april",
            "may",
            "june",
            "july",
            "august",
            "september",
            "october",
            "november",
            "december",
        ],
        1,
    )
}
_MONTH_RE = "|".join(_MONTHS) + "|" + "|".join(m[:3] for m in _MONTHS)
_DATE_RES = [
    # 4 October 2026 – 18:22:41 UTC
    re.compile(
        rf"\b(?P<d>\d{{1,2}})\s+(?P<m>{_MONTH_RE})\.?,?\s+(?P<y>\d{{4}})"
        r"(?:\s*[–—,-]?\s*(?P<H>\d{1,2}):(?P<M>\d{2})(?::(?P<S>\d{2}))?)?",
        re.I,
    ),
    # October 4, 2026 18:22
    re.compile(
        rf"\b(?P<m>{_MONTH_RE})\.?\s+(?P<d>\d{{1,2}}),?\s+(?P<y>\d{{4}})"
        r"(?:\s*[–—,-]?\s*(?P<H>\d{1,2}):(?P<M>\d{2})(?::(?P<S>\d{2}))?)?",
        re.I,
    ),
    # 2026-10-04 18:22:41
    re.compile(r"\b(?P<y>\d{4})-(?P<mm>\d{2})-(?P<d>\d{2})(?:[ T](?P<H>\d{2}):(?P<M>\d{2})(?::(?P<S>\d{2}))?)?"),
]
_MANIFEST_RE = re.compile(r"(?<!\d)(\d{15,20})(?!\d)")


def _parse_date(line: str) -> tuple[str, int] | None:
    """(ISO-8601 UTC, position) of the first date in the line."""
    best: tuple[str, int] | None = None
    for rx in _DATE_RES:
        m = rx.search(line)
        if not m or (best and best[1] <= m.start()):
            continue
        g = m.groupdict()
        month = (
            int(g["mm"])
            if g.get("mm")
            else _MONTHS.get(g["m"].lower()) or next(i for n, i in _MONTHS.items() if n.startswith(g["m"].lower()[:3]))
        )
        try:
            dt = datetime(
                int(g["y"]), month, int(g["d"]), int(g["H"] or 0), int(g["M"] or 0), int(g["S"] or 0), tzinfo=UTC
            )
        except ValueError:
            continue
        best = (dt.isoformat().replace("+00:00", "Z"), m.start())
    return best


def parse_manifest_list(text: str) -> list[dict[str, Any]]:
    """Manifest ids and dates from a list copied from SteamDB (or typed: ``2024-05-01 1234567890123456789``).

    A line's date belongs to the manifest on the same line, else to the next manifest found. Newest first;
    duplicates dropped; a manifest without any date gets ``date: None``."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    pending: str | None = None
    for line in text.splitlines():
        d = _parse_date(line)
        ids = [m.group(1) for m in _MANIFEST_RE.finditer(line)]
        if d and not ids:
            pending = d[0]
            continue
        for mid in ids:
            date = d[0] if d else pending
            pending = None
            if mid not in seen:
                seen.add(mid)
                out.append({"manifest": mid, "date": date})
    out.sort(key=lambda r: r["date"] or "", reverse=True)
    return out


# ------------------------------------------------------------------ state
@dataclass
class DownloadJob:
    id: str
    appid: str
    game: str
    depot: str
    manifest: str
    date: str | None
    status: str = "WAITING_FOR_STEAM"  # → DOWNLOADED → CAPTURED | FAILED
    detail: str = ""
    log_offset: int = 0
    started_at: str = ""
    finished_at: str | None = None
    builds: list[dict[str, Any]] = field(default_factory=list)
    compared: list[str] = field(default_factory=list)

    @property
    def command(self) -> str:
        return f"download_depot {self.appid} {self.depot} {self.manifest}"


def _state_path(ws: Workspace) -> Path:
    return ws.path / STATE_FILE


def load_jobs(ws: Workspace) -> list[DownloadJob]:
    p = _state_path(ws)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [DownloadJob(**j) for j in data.get("jobs", [])]


def _save_jobs(ws: Workspace, jobs: list[DownloadJob]) -> None:
    p = _state_path(ws)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"version": 1, "jobs": [asdict(j) for j in jobs[-500:]]}, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def _update(ws: Workspace, job: DownloadJob) -> DownloadJob:
    jobs = [j for j in load_jobs(ws) if j.id != job.id] + [job]
    _save_jobs(ws, jobs)
    return job


def get_job(ws: Workspace, job_id: str) -> DownloadJob:
    for j in load_jobs(ws):
        if j.id == job_id:
            return j
    raise AcetError("ACET-STEAM-002", f"unknown Steam download {job_id}")


def captured_manifests(ws: Workspace) -> set[str]:
    return {j.manifest for j in load_jobs(ws) if j.status == "CAPTURED"}


# ------------------------------------------------------------------ download through the Steam console
def depot_dir(root: Path, appid: str, depot: str) -> Path:
    """Where the Steam client writes ``download_depot`` results (its own scratch folder)."""
    return root / "steamapps" / "content" / f"app_{int(appid)}" / f"depot_{int(depot)}"


def console_log(root: Path) -> Path:
    return root / "logs" / "console_log.txt"


def begin(
    ws: Workspace, appid: str, game: str, depot: str, manifest: str, date: str | None, root: Path | None = None
) -> DownloadJob:
    """Prepare one download: clear Steam's scratch folder for this depot (a previous version must not mix with
    this one) and remember where Steam's console log ends now. Returns the job; its ``command`` goes to Steam."""
    root = root or steam_root()
    if root is None:
        raise AcetError("ACET-STEAM-001", "Steam is not installed on this PC (no Steam folder found)")
    for v in (appid, depot, manifest):
        if not str(v).isdigit():
            raise AcetError("ACET-STEAM-002", f"not a Steam id: {v!r}")
    target = depot_dir(root, appid, depot)
    if target.exists():
        shutil.rmtree(target)
    log = console_log(root)
    offset = log.stat().st_size if log.is_file() else 0
    job = DownloadJob(
        uuid.uuid4().hex[:12],
        str(appid),
        game,
        str(depot),
        str(manifest),
        date,
        log_offset=offset,
        started_at=utc_now_iso(),
    )
    return _update(ws, job)


def poll(ws: Workspace, job_id: str, root: Path | None = None) -> DownloadJob:
    """Read Steam's console log written since :func:`begin`: DOWNLOADED on "Depot download complete" for this
    depot, FAILED on a failure line naming it; unchanged otherwise."""
    job = get_job(ws, job_id)
    if job.status != "WAITING_FOR_STEAM":
        return job
    root = root or steam_root()
    if root is None:
        return job
    log = console_log(root)
    try:
        with log.open("rb") as f:
            size = log.stat().st_size
            f.seek(job.log_offset if job.log_offset <= size else 0)  # Steam rotates its logs at start-up
            text = f.read().decode("utf-8", errors="replace")
    except OSError:
        return job
    tag = f"depot_{int(job.depot)}"
    for line in text.splitlines():
        low = line.lower()
        if "depot download complete" in low and tag in line:
            job.status, job.detail = "DOWNLOADED", line.strip()[:300]
            break
        names_it = "download_depot" in low or ("depot" in low and job.depot in line)
        if names_it and any(w in low for w in ("failed", "error", "invalid", "no license", "not found")):
            job.status, job.detail = "FAILED", line.strip()[:300]
            job.finished_at = utc_now_iso()
            break
    return _update(ws, job) if job.status != "WAITING_FOR_STEAM" else job


def mark_downloaded(ws: Workspace, job_id: str) -> DownloadJob:
    """The user says Steam finished (when its log line was not seen)."""
    job = get_job(ws, job_id)
    job.status, job.detail = "DOWNLOADED", "marked finished by the user"
    return _update(ws, job)


def capture(
    ws: Workspace, job_id: str, root: Path | None = None, *, delete_download: bool = True, compare: bool = True
) -> DownloadJob:
    """Import the anti-cheat folders of a finished download as builds dated at the manifest date, keep a copy in
    the versions folder, compare each with the version currently installed, then delete Steam's download."""
    from acet.application.products import create_product
    from acet.domain.enums import ObservationSourceType
    from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build
    from acet.storage import repositories as repo

    job = get_job(ws, job_id)
    root = root or steam_root()
    if root is None:
        raise AcetError("ACET-STEAM-001", "Steam is not installed on this PC (no Steam folder found)")
    src_dir = depot_dir(root, job.appid, job.depot)
    folders = _ac_folders(src_dir) if src_dir.is_dir() else []
    if not folders:
        job.status = "FAILED"
        job.detail = (
            "Steam's download folder is missing"
            if not src_dir.is_dir()
            else "no anti-cheat folder in this depot: choose the game's other depot"
        )
        job.finished_at = utc_now_iso()
        return _update(ws, job)
    when = job.date or utc_now_iso()
    day = (job.date or "date unknown")[:10]
    job.builds = []
    for product, folder in folders:
        if repo.find_product(ws.db.conn, product) is None:
            create_product(ws, product)
        label = f"{job.game} {day} (manifest {job.manifest})"
        snap = ws.path / "watch" / "snapshots" / f"steam-{job.id}-{uuid.uuid4().hex[:6]}"
        try:
            entries = []
            for rel, p in watch.collect_files([str(folder)]):
                dest = snap / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, dest)
                digest = watch._sha256(dest)
                if digest != watch._sha256(p):
                    raise AcetError("ACET-STEAM-002", f"{rel} changed while being copied")
                entries.append({"name": rel, "sha256": digest, "size": dest.stat().st_size})
            r = import_build(
                ws,
                ImportRequest(
                    [snap],
                    product,
                    release_label=label,
                    observed_at=when,
                    source_type=ObservationSourceType.ARCHIVE,
                    source_label=f"steam:{job.appid}/{job.depot}/{job.manifest}",
                    on_duplicate=DuplicatePolicy.ADD_OBSERVATION,
                ),
            )
            archive = _archive(ws, product, job, snap, entries, label, r.build_id)
            job.builds.append(
                {
                    "product": product,
                    "build_id": r.build_id,
                    "created_build": r.created_build,
                    "files": len(entries),
                    "archive_path": str(archive),
                }
            )
        finally:
            shutil.rmtree(snap, ignore_errors=True)
    job.status, job.finished_at = "CAPTURED", utc_now_iso()
    job.detail = ", ".join(f"{b['product']}: {b['files']} file(s)" for b in job.builds)
    if compare:
        job.compared = compare_with_current(ws, job)
    if delete_download:
        shutil.rmtree(src_dir, ignore_errors=True)
    return _update(ws, job)


def _archive(
    ws: Workspace, product: str, job: DownloadJob, snap: Path, entries: list[dict[str, Any]], label: str, build_id: str
) -> Path:
    """<versions folder>/<product>/<manifest date> <game> (Steam manifest <id>)/ + manifest.json."""
    day = (job.date or "0000-00-00T00:00:00")[:19].replace("T", " ").replace(":", "")
    dest = (
        watch.archive_dir(ws) / watch._safe(product) / watch._safe(f"{day} {job.game} (Steam manifest {job.manifest})")
    )
    if dest.exists():
        shutil.rmtree(dest)  # same manifest captured again: same bytes, refresh the copy
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(snap, dest)
    manifest = {
        "product": product,
        "source": f"Steam {job.game} (app {job.appid}, depot {job.depot})",
        "steam_manifest": job.manifest,
        "manifest_date": job.date,
        "captured_at": utc_now_iso(),
        "build_id": build_id,
        "build_label": label,
        "files": entries,
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return dest


def current_build(ws: Workspace, appid: str, product: str, root: Path | None = None) -> str | None:
    """Build id of the version installed now: the watched source of that game's anti-cheat folder (checked now)."""
    root = root or steam_root()
    game = next((g for g in installed_games(root) if g["appid"] == appid), None) if root else None
    if game is None:
        return None
    dirs = {d.lower() for d in game["anticheat_dirs"]}
    src = next(
        (s for s in watch.list_sources(ws) if s.product == product and any(p.lower() in dirs for p in s.paths)), None
    )
    if src is None:
        path = next(
            d
            for d in game["anticheat_dirs"]
            if Path(d).name.lower()
            in {
                sub.lower()
                for p in watch._presets()["products"]
                if p["product"] == product
                for sub in p.get("game_subfolders", [])
            }
        )
        src = watch.add_source(ws, f"{game['name']} — {product}", product, [path], auto=True)
    if src.last_build_id is None or src.last_status != "UNCHANGED":
        watch.scan_source(ws, src.id)
        src = next(s for s in watch.list_sources(ws) if s.id == src.id)
    return src.last_build_id


def compare_with_current(ws: Workspace, job: DownloadJob) -> list[str]:
    """Compare each captured old version with the installed one (STANDARD) when the Engine Pack allows it."""
    from acet.analysis.orchestrator import compare_builds
    from acet.platform import engine_manager as em

    out = []
    for b in job.builds:
        try:
            cur = current_build(ws, job.appid, b["product"])
        except (AcetError, StopIteration) as exc:
            out.append(f"{b['product']}: current version not found ({exc})")
            continue
        if cur is None:
            out.append(f"{b['product']}: current version not captured yet")
        elif cur == b["build_id"]:
            out.append(f"{b['product']}: identical to the version installed now")
        elif em.profile_gate("STANDARD@1")["state"] not in ("READY", "DEGRADED"):
            out.append(f"{b['product']}: install the Engine Pack to compare automatically")
        else:
            try:
                s = compare_builds(ws, b["build_id"], cur, "STANDARD@1")
                out.append(f"{b['product']} {(job.date or '')[:10]} → installed: comparison {s.status} — see Changes")
            except Exception as exc:  # the version is captured; a failed comparison is reported, never fatal
                out.append(f"{b['product']}: comparison failed ({exc})")
    return out
