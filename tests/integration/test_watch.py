"""Local version watch: a changed set of executables becomes a new build; nothing is imported half-way."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from acet.application import watch
from acet.domain.error_codes import AcetError

DEMO = Path(__file__).resolve().parents[2] / "datasets" / "demo" / "builds"


def _install(dest: Path, version: str) -> None:
    """Simulate an anti-cheat updater replacing its files in place (plus non-executables that are ignored)."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(DEMO / version, dest)
    (dest / "readme.txt").write_text("not an executable")


def _builds(ws) -> int:  # type: ignore[no-untyped-def]
    return ws.db.conn.execute("SELECT COUNT(*) FROM build").fetchone()[0]


def test_new_versions_are_captured_and_imported(ws, tmp_path):
    folder = tmp_path / "Common Files" / "Guard"
    _install(folder, "v1")
    src = watch.add_source(ws, "Guard (system)", "Guard", [str(folder)])
    r1 = watch.scan_source(ws, src.id)
    assert r1.status == "NEW_VERSION" and r1.created_build and _builds(ws) == 1
    assert all(not f["name"].endswith(".txt") for f in r1.files)  # executables only
    assert watch.scan_source(ws, src.id).status == "UNCHANGED" and _builds(ws) == 1
    _install(folder, "v2")  # the product updated itself
    r2 = watch.scan_source(ws, src.id)
    assert r2.status == "NEW_VERSION" and r2.created_build and r2.build_id != r1.build_id and _builds(ws) == 2
    _install(folder, "v1")  # rolled back: same bytes as the first build -> re-observed, not duplicated
    r3 = watch.scan_source(ws, src.id)
    assert r3.status == "NEW_VERSION" and not r3.created_build and r3.build_id == r1.build_id and _builds(ws) == 2
    s = watch.list_sources(ws)[0]
    assert [h["build_id"] for h in s.history] == [r1.build_id, r2.build_id, r1.build_id]
    assert not (ws.path / "watch" / "snapshots").exists()  # snapshots are dropped once imported
    product = ws.db.conn.execute("SELECT name FROM product").fetchall()
    assert [p[0] for p in product] == ["Guard"]  # created on first add


def test_locked_or_changing_files_are_never_imported(ws, tmp_path, monkeypatch):
    folder = tmp_path / "Guard"
    _install(folder, "v1")
    src = watch.add_source(ws, "Guard", "Guard", [str(folder)])
    real = watch._sha256

    def locked(p):  # type: ignore[no-untyped-def]
        if Path(p).name == "guardcore.dll" and folder in Path(p).parents:
            raise PermissionError(13, "The process cannot access the file")
        return real(p)

    monkeypatch.setattr(watch, "_sha256", locked)
    r = watch.scan_source(ws, src.id)
    assert r.status == "LOCKED" and _builds(ws) == 0 and watch.list_sources(ws)[0].last_fingerprint is None
    reads: dict[Path, int] = {}

    def changing(p):  # type: ignore[no-untyped-def]
        p = Path(p)  # a source file differs when re-read after the copy: an update is being written
        reads[p] = reads.get(p, 0) + 1
        return "0" * 64 if folder in p.parents and reads[p] >= 2 else real(p)

    monkeypatch.setattr(watch, "_sha256", changing)
    r = watch.scan_source(ws, src.id)
    assert r.status == "UNSTABLE" and _builds(ws) == 0 and not (ws.path / "watch" / "snapshots").exists()
    monkeypatch.setattr(watch, "_sha256", real)
    assert watch.scan_source(ws, src.id).status == "NEW_VERSION" and _builds(ws) == 1  # next scan succeeds


def test_sources_are_validated_and_manageable(ws, tmp_path):
    with pytest.raises(AcetError):
        watch.add_source(ws, "x", "Guard", [str(tmp_path / "missing")])
    folder = tmp_path / "g"
    _install(folder, "v1")
    a = watch.add_source(ws, "Guard", "Guard", [str(folder)])
    assert watch.add_source(ws, "Guard again", "Guard", [str(folder)]).id == a.id  # no duplicate source
    watch.set_enabled(ws, a.id, False)
    assert watch.scan_source(ws, a.id).status == "DISABLED" and watch.scan_all(ws) == []
    watch.set_interval(ws, 60)
    assert watch.load_state(ws)["interval_minutes"] == 60
    with pytest.raises(AcetError):
        watch.set_interval(ws, 1)
    watch.remove_source(ws, a.id)
    assert watch.list_sources(ws) == []
    empty = tmp_path / "empty"
    empty.mkdir()
    b = watch.add_source(ws, "Empty", "Guard", [str(empty)])
    assert watch.scan_source(ws, b.id).status == "EMPTY"


def test_detection_only_suggests_locations_that_hold_executables(tmp_path, monkeypatch):
    pf = tmp_path / "Program Files (x86)"
    _install(pf / "Common Files" / "BattlEye", "v1")
    (pf / "EasyAntiCheat_EOS").mkdir(parents=True)  # present but empty: not suggested
    games = tmp_path / "steamapps" / "common"
    _install(games / "Some Game" / "EasyAntiCheat", "v2")
    _install(games / "Other Game" / "Binaries" / "BattlEye", "v1")
    (games / "Plain Game").mkdir()
    monkeypatch.setenv("ProgramFiles(x86)", str(pf))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "nothing"))
    monkeypatch.setattr(watch, "steam_libraries", lambda: [])
    found = watch.detect_candidates(extra_game_roots=[games])
    got = {(c["product"], Path(c["paths"][0]).relative_to(tmp_path).as_posix()) for c in found}
    assert got == {
        ("BattlEye", "Program Files (x86)/Common Files/BattlEye"),
        ("EasyAntiCheat", "steamapps/common/Some Game/EasyAntiCheat"),
        ("BattlEye", "steamapps/common/Other Game/Binaries/BattlEye"),
    }


@pytest.mark.real_watch_discovery
def test_steam_library_folders_are_read(tmp_path, monkeypatch):
    steam = tmp_path / "Steam"
    (steam / "steamapps" / "common").mkdir(parents=True)
    lib2 = tmp_path / "Games" / "SteamLibrary"
    (lib2 / "steamapps" / "common").mkdir(parents=True)
    (steam / "steamapps" / "libraryfolders.vdf").write_text(
        "".join(
            f'\t"{i}"\n\t{{\n\t\t"path"\t\t"{str(p).replace(chr(92), chr(92) * 2)}"\n\t}}\n'
            for i, p in enumerate((steam, lib2))
        ).join(('"libraryfolders"\n{\n', "}\n"))
    )
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "none"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "nohome")
    assert set(watch.steam_libraries()) == {steam / "steamapps" / "common", lib2 / "steamapps" / "common"}


def test_cli_watch_add_scan_list(tmp_path):
    import json
    import os
    import subprocess
    import sys

    folder = tmp_path / "Guard"
    _install(folder, "v1")
    env = {**os.environ, "ACET_HOME": str(tmp_path / "home")}

    def acet(*a: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-m", "acet", *a], capture_output=True, text=True, env=env, timeout=600)

    ws = json.loads(acet("workspace", "create", "w", "--json").stdout)["path"]
    env["ACET_WORKSPACE"] = ws
    assert acet("watch", "add", "Guard", str(folder), "--label", "Guard (test)").returncode == 0
    first = json.loads(acet("watch", "scan", "--json").stdout)
    assert [r["status"] for r in first] == ["NEW_VERSION"]
    assert [r["status"] for r in json.loads(acet("watch", "scan", "--json").stdout)] == ["UNCHANGED"]
    listed = acet("watch", "list")
    assert "Guard (test)" in listed.stdout and "versions=1" in listed.stdout


def test_fully_automatic_cycle_finds_copies_and_imports(ws, tmp_path, monkeypatch):
    """Nothing to click: discovery adds the installation, each new version is kept as plain files + imported."""
    import json

    pf = tmp_path / "pf"
    folder = pf / "Common Files" / "BattlEye"
    _install(folder, "v1")
    monkeypatch.setenv("ProgramFiles(x86)", str(pf))
    state = watch.load_state(ws)
    assert state["auto"] and state["auto_discover"] and state["auto_compare"]  # automatic by default
    c1 = watch.run_cycle(ws)
    assert c1["added"] == ["BattlEye (system)"] and [r.status for r in c1["results"]] == ["NEW_VERSION"]
    r1 = c1["results"][0]
    arch = Path(r1.archive_path)
    assert arch.is_relative_to(Path(watch.default_archive_dir()) / "BattlEye")
    assert sorted(p.name for p in arch.iterdir()) == ["BattlEye", "manifest.json"]
    man = json.loads((arch / "manifest.json").read_text(encoding="utf-8"))
    assert man["build_id"] == r1.build_id and len(man["files"]) == 2 and r1.previous_build_id is None
    c2 = watch.run_cycle(ws)  # nothing new, nothing re-added
    assert c2["added"] == [] and [r.status for r in c2["results"]] == ["UNCHANGED"]
    _install(folder, "v2")
    r3 = watch.run_cycle(ws)["results"][0]
    assert r3.status == "NEW_VERSION" and r3.previous_build_id == r1.build_id and r3.archive_path != r1.archive_path
    assert len(list((Path(watch.default_archive_dir()) / "BattlEye").iterdir())) == 2  # one folder per version
    # the user removes the automatically found source: it is never added back
    watch.remove_source(ws, watch.list_sources(ws)[0].id)
    assert watch.run_cycle(ws)["added"] == [] and watch.list_sources(ws) == []


def test_archive_folder_and_options(ws, tmp_path):
    watch.set_option(ws, "archive_dir", str(tmp_path / "Mes versions"))
    assert watch.archive_dir(ws) == tmp_path / "Mes versions"
    watch.set_option(ws, "auto_compare", False)
    assert watch.load_state(ws)["auto_compare"] is False
    with pytest.raises(AcetError):
        watch.set_option(ws, "nope", True)


def test_background_task_command_runs_one_cycle_for_this_workspace(ws):
    cmd = watch.scheduled_task_command(ws, 30)
    assert cmd[:3] == ["schtasks", "/Create", "/F"] and cmd[cmd.index("/MO") + 1] == "30"
    target = cmd[cmd.index("/TR") + 1]
    assert "watch cycle" in target and str(ws.path) in target


def test_new_version_is_compared_with_the_previous_one_when_engines_are_ready(ws, tmp_path, monkeypatch):
    from acet.analysis import orchestrator
    from acet.platform import engine_manager as em

    folder = tmp_path / "g"
    _install(folder, "v1")
    watch.add_source(ws, "Guard", "Guard", [str(folder)])
    calls = []

    class Summary:
        status = "COMPLETED"

    monkeypatch.setattr(em, "profile_gate", lambda ref: {"state": "READY"})
    monkeypatch.setattr(orchestrator, "compare_builds", lambda w, a, b, p: calls.append((a, b, p)) or Summary())
    first = watch.run_cycle(ws)
    assert first["compared"] == [] and calls == []  # nothing to compare with yet
    _install(folder, "v2")
    second = watch.run_cycle(ws)
    r = second["results"][0]
    assert calls == [(r.previous_build_id, r.build_id, "STANDARD@1")]
    assert "compared with the previous version (COMPLETED)" in second["compared"][0]
    monkeypatch.setattr(em, "profile_gate", lambda ref: {"state": "UNAVAILABLE"})
    _install(folder, "v1")  # back to v1: same bytes, re-observed only -> no new comparison
    assert watch.run_cycle(ws)["compared"] == [] and len(calls) == 1


def test_cli_watch_cycle_is_the_automatic_round(tmp_path):
    import json
    import os
    import subprocess
    import sys

    pf = tmp_path / "pf"
    _install(pf / "EasyAntiCheat_EOS", "v1")
    env = {**os.environ, "ACET_HOME": str(tmp_path / "home"), "ProgramFiles(x86)": str(pf),
           "ACET_WATCH_ARCHIVE": str(tmp_path / "versions")}  # fmt: skip
    ws = json.loads(
        subprocess.run(
            [sys.executable, "-m", "acet", "workspace", "create", "w", "--json"],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        ).stdout
    )["path"]
    out = subprocess.run([sys.executable, "-m", "acet", "watch", "cycle", "-w", ws, "--json"], capture_output=True,
                         text=True, env=env, timeout=600)  # fmt: skip
    cycle = json.loads(out.stdout)
    assert cycle["added"] == ["EasyAntiCheat (system)"] and cycle["results"][0]["status"] == "NEW_VERSION"
    assert (tmp_path / "versions" / "EasyAntiCheat").is_dir()
