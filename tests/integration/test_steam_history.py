"""Older versions through the signed-in Steam client: game/depot discovery, the pasted SteamDB list, the console
download followed in Steam's log, capture dated at the manifest date, comparison with the installed version."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from acet.application import steam_history as sh
from acet.application import watch
from acet.domain.error_codes import AcetError

DEMO = Path(__file__).resolve().parents[2] / "datasets" / "demo" / "builds"
APP, DEPOT, CURRENT = "221100", "221101", "1111111111111111111"


def _steam(tmp_path: Path) -> Path:
    """A Steam client folder: a second library holding a game with a BattlEye folder (version v2 installed)."""
    root = tmp_path / "Steam"
    lib = tmp_path / "Games" / "SteamLibrary"
    (root / "steamapps").mkdir(parents=True)
    (root / "config").mkdir()
    (root / "logs").mkdir()
    (root / "logs" / "console_log.txt").write_text("[2026-10-01 10:00:00] Startup\n")
    lib_vdf = str(lib).replace("\\", "\\\\")
    (root / "steamapps" / "libraryfolders.vdf").write_text(
        f'"libraryfolders"\n{{\n\t"0"\n\t{{\n\t\t"path"\t\t"{root}"\n\t}}\n'
        f'\t"1"\n\t{{\n\t\t"path"\t\t"{lib_vdf}"\n\t\t"apps"\n\t\t{{\n\t\t\t"{APP}"\t\t"123"\n\t\t}}\n\t}}\n}}\n'
    )
    (root / "config" / "loginusers.vdf").write_text(
        '"users"\n{\n\t"76561198000000001"\n\t{\n\t\t"AccountName"\t\t"someone"\n\t\t"PersonaName"\t\t"Some One"\n'
        '\t\t"MostRecent"\t\t"1"\n\t}\n}\n'
    )
    (lib / "steamapps").mkdir(parents=True)
    (lib / "steamapps" / f"appmanifest_{APP}.acf").write_text(
        f'"AppState"\n{{\n\t"appid"\t\t"{APP}"\n\t"name"\t\t"Some Game"\n\t"installdir"\t\t"SomeGame"\n'
        f'\t"InstalledDepots"\n\t{{\n\t\t"{DEPOT}"\n\t\t{{\n\t\t\t"manifest"\t\t"{CURRENT}"\n\t\t\t"size"\t\t"900"\n'
        '\t\t}\n\t\t"221102"\n\t\t{\n\t\t\t"manifest"\t\t"2222222222222222222"\n\t\t\t"size"\t\t"10"\n\t\t}\n\t}\n}\n'
    )
    # a game without anti-cheat folder is not listed
    (lib / "steamapps" / "appmanifest_7.acf").write_text(
        '"AppState"\n{\n"appid" "7"\n"name" "Other"\n"installdir" "Other"\n}\n'
    )
    (lib / "steamapps" / "common" / "Other").mkdir(parents=True)
    shutil.copytree(DEMO / "v2", lib / "steamapps" / "common" / "SomeGame" / "BattlEye")
    return root


def _steam_downloads(root: Path, manifest: str, version: str, *, complete: bool = True) -> None:
    """What the Steam client does after `download_depot`: files in its content folder, a line in its log."""
    dest = sh.depot_dir(root, APP, DEPOT)
    shutil.copytree(DEMO / version, dest / "BattlEye")
    (dest / "game.pak").write_text("game data, not an executable")
    if complete:
        with (root / "logs" / "console_log.txt").open("a") as f:
            f.write(f'[2026-10-11 10:00:00] Depot download complete : "{dest}" (3 files, manifest {manifest})\n')


def test_games_depots_and_signed_in_account_are_read_from_steam(tmp_path):
    root = _steam(tmp_path)
    games = sh.installed_games(root)
    assert [g["name"] for g in games] == ["Some Game"]
    g = games[0]
    assert g["appid"] == APP and g["products"] == ["BattlEye"]
    assert [d["depot"] for d in g["depots"]] == [DEPOT, "221102"]  # largest (main) depot first
    assert g["depots"][0]["manifest"] == CURRENT
    acc = sh.signed_in_account(root)
    assert acc["account"] == "someone" and acc["persona"] == "Some One"
    assert "password" not in json.dumps(acc).lower()
    assert sh.steamdb_url(DEPOT) == f"https://steamdb.info/depot/{DEPOT}/manifests/"


def test_no_steam_is_a_clear_error():
    assert sh.steam_root() is None  # the test machine's Steam is never looked at
    with pytest.raises(AcetError) as e:
        sh.installed_games()
    assert e.value.code == "ACET-STEAM-001"


def test_manifest_list_pasted_from_steamdb_is_parsed():
    pasted = (
        "Seen Date\tRelative\tManifest ID\n"
        "4 October 2026 – 18:22:41 UTC\t6 days ago\t5743210987654321098\n"
        "12 August 2026 – 09:05:00 UTC\t2 months ago\t1234567890123456789\n"
        "March 3, 2025\n"
        "8888888888888888888\n"
        "2024-05-01 4444444444444444444\n"
        "4 October 2026 – 18:22:41 UTC\t6 days ago\t5743210987654321098\n"  # pasted twice
        "9999999999999999999\n"
    )
    rows = sh.parse_manifest_list(pasted)
    assert [(r["manifest"], r["date"]) for r in rows] == [
        ("5743210987654321098", "2026-10-04T18:22:41Z"),
        ("1234567890123456789", "2026-08-12T09:05:00Z"),
        ("8888888888888888888", "2025-03-03T00:00:00Z"),
        ("4444444444444444444", "2024-05-01T00:00:00Z"),
        ("9999999999999999999", None),
    ]


def test_old_version_is_downloaded_by_steam_captured_dated_and_compared(ws, tmp_path, monkeypatch):
    root = _steam(tmp_path)
    old = "5743210987654321098"
    sh.depot_dir(root, APP, DEPOT).mkdir(parents=True)
    (sh.depot_dir(root, APP, DEPOT) / "leftover.dll").write_bytes(b"MZ older run")
    job = sh.begin(ws, APP, "Some Game", DEPOT, old, "2026-08-12T09:05:00Z", root)
    assert job.command == f"download_depot {APP} {DEPOT} {old}"
    assert not sh.depot_dir(root, APP, DEPOT).exists()  # a previous download never mixes with this one
    assert sh.poll(ws, job.id, root).status == "WAITING_FOR_STEAM"
    _steam_downloads(root, old, "v1")
    assert sh.poll(ws, job.id, root).status == "DOWNLOADED"

    compared: list[tuple[str, str]] = []

    def fake_compare(_ws, left, right, profile):  # type: ignore[no-untyped-def]
        compared.append((left, right))
        return type("S", (), {"status": "COMPLETED"})()

    import acet.analysis.orchestrator as orch
    from acet.platform import engine_manager as em

    monkeypatch.setattr(orch, "compare_builds", fake_compare)
    monkeypatch.setattr(em, "profile_gate", lambda p: {"state": "READY"})
    monkeypatch.setattr(sh, "steam_root", lambda: root)
    done = sh.capture(ws, job.id, root)
    assert done.status == "CAPTURED" and len(done.builds) == 1
    b = done.builds[0]
    assert b["product"] == "BattlEye" and b["created_build"] and b["files"] == 2
    obs = ws.db.conn.execute("SELECT observed_at FROM observation WHERE build_id=?", (b["build_id"],)).fetchall()
    assert [o[0] for o in obs] == ["2026-08-12T09:05:00Z"]  # dated at the manifest date, not today
    archive = Path(b["archive_path"])
    assert archive.parent.name == "BattlEye" and "2026-08-12" in archive.name and old in archive.name
    meta = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    assert meta["steam_manifest"] == old and len(meta["files"]) == 2
    assert not (archive / "game.pak").exists()  # only the anti-cheat executables are kept
    assert not sh.depot_dir(root, APP, DEPOT).exists()  # Steam's full download is deleted
    # the installed version (v2) was captured through the watch and compared with the old one
    cur = next(s for s in watch.list_sources(ws) if s.product == "BattlEye")
    assert compared == [(b["build_id"], cur.last_build_id)] and cur.last_build_id != b["build_id"]
    assert "comparison COMPLETED" in done.compared[0]
    assert sh.captured_manifests(ws) == {old}


def test_failed_or_wrong_depot_is_reported_not_imported(ws, tmp_path):
    root = _steam(tmp_path)
    job = sh.begin(ws, APP, "Some Game", DEPOT, "1234567890123456789", None, root)
    with (root / "logs" / "console_log.txt").open("a") as f:
        f.write(f"[2026-10-11 10:00:00] Depot download failed : Download of depot {DEPOT} failed (No license)\n")
    assert sh.poll(ws, job.id, root).status == "FAILED"
    job2 = sh.begin(ws, APP, "Some Game", "221102", "2222222222222222222", None, root)
    dest = sh.depot_dir(root, APP, "221102")
    dest.mkdir(parents=True)
    (dest / "data.pak").write_text("no anti-cheat here")
    sh.mark_downloaded(ws, job2.id)
    r = sh.capture(ws, job2.id, root, compare=False)
    assert r.status == "FAILED" and "other depot" in r.detail
    assert ws.db.conn.execute("SELECT COUNT(*) FROM build").fetchone()[0] == 0
    with pytest.raises(AcetError):
        sh.begin(ws, APP, "Some Game", DEPOT, "12; quit", None, root)  # only numeric ids reach the console


def test_cli_steam_games_and_parse(tmp_path, capsys, monkeypatch):
    from acet.cli.main import main

    root = _steam(tmp_path)
    monkeypatch.setenv("ACET_STEAM_ROOT", str(root))
    assert main(["steam", "games"]) == 0
    assert "Some Game" in capsys.readouterr().out
    lst = tmp_path / "list.txt"
    lst.write_text("4 October 2026 – 18:22:41 UTC\t6 days ago\t5743210987654321098\n")
    assert main(["steam", "parse", str(lst)]) == 0
    assert "5743210987654321098  2026-10-04" in capsys.readouterr().out
