"""CLI parity and exit codes (spec §53, ACC-042, ACC-043)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acet.cli.main import EXIT_OK, EXIT_PARTIAL, EXIT_SYSTEM, EXIT_USER, main
from tests.fixtures import build_a


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.acceptance("ACC-042", "ACC-043")
def test_cli_end_to_end_exit_codes(capsys, tmp_path):
    code, out, _ = run(capsys, "workspace", "create", "demo", "--root", str(tmp_path / "w"), "--json")
    assert code == EXIT_OK
    wpath = json.loads(out)["path"]
    w = ["--workspace", wpath]

    code, out, _ = run(capsys, "product", "create", "Fictional Guard", *w, "--json")
    assert code == EXIT_OK
    pid = json.loads(out)["id"]

    src = build_a(tmp_path / "a")
    code, out, _ = run(capsys, "import", str(src), "--product", pid, "--release", "1.0", *w, "--json")
    assert code == EXIT_OK
    build_id = json.loads(out)["build_id"]

    code, _, err = run(capsys, "import", str(src), "--product", pid, *w, "--json")
    assert code == EXIT_USER
    assert json.loads(err)["error"]["code"] == "ACET-IMP-004"

    code, out, _ = run(capsys, "import", str(src), "--product", pid, "--on-duplicate", "add-observation", *w, "--json")
    assert code == EXIT_OK and json.loads(out)["created_build"] is False

    code, out, _ = run(capsys, "builds", "list", *w, "--json")
    assert code == EXIT_OK and [b["observations"] for b in json.loads(out)] == [2]

    code, out, _ = run(capsys, "builds", "verify", build_id, *w)
    assert code == EXIT_OK

    # Doctor: engines are absent in CI → DEGRADED → partial success (10), never a crash.
    code, out, _ = run(capsys, "doctor", *w, "--json")
    assert code == EXIT_PARTIAL
    assert json.loads(out)["health"] == "DEGRADED"

    code, out, _ = run(capsys, "reconcile", *w, "--json")
    assert code == EXIT_OK and json.loads(out)["clean"] is True

    code, out, _ = run(capsys, "backup", *w, "--json")
    assert code == EXIT_OK

    # Integrity failure is a system failure (40) with an actionable message, no stack trace.
    for blob in (tmp_path / "w").rglob("artifacts/sha256/*/*/*"):
        blob.chmod(0o644)
        blob.write_bytes(b"x")
        break
    code, _, err = run(capsys, "builds", "verify", build_id, *w)
    assert code == EXIT_SYSTEM
    assert "ACET-STO-002" in err and "action:" in err and "Traceback" not in err


def test_cli_user_errors(capsys, tmp_path):
    code, _, err = run(capsys, "builds", "list", "--workspace", str(tmp_path / "nowhere"))
    assert code == EXIT_USER and "ACET-WS-001" in err
    code, _, _ = run(capsys, "no-such-command")
    assert code == EXIT_USER
    code, _, err = run(capsys, "analyze", "x", "--workspace", str(tmp_path / "nowhere"))
    assert code == EXIT_USER and "ACET-WS-001" in err


def test_every_command_is_registered():
    """Guard: each cmd_* handler must be reachable from the parser (a silent registration miss happened once)."""
    import acet.cli.main as m

    handlers = {name for name in dir(m) if name.startswith("cmd_")}
    parser = m.build_parser()
    reachable: set[str] = set()

    def walk(p):  # type: ignore[no-untyped-def]
        fn = p.get_default("func")
        if fn is not None:
            reachable.add(fn.__name__)
        for action in p._actions:
            if hasattr(action, "choices") and isinstance(action.choices, dict):
                for sp in action.choices.values():
                    walk(sp)

    walk(parser)
    assert handlers <= reachable, sorted(handlers - reachable)


def _doctor_full_subprocess(tmp_path, extra_env):
    import os
    import subprocess
    import sys

    env = {
        k: v for k, v in os.environ.items() if not k.startswith(("ACET_GHIDRA", "GHIDRA_")) and k != "ACET_WORKSPACE"
    }
    env.update(extra_env, ACET_HOME=str(tmp_path / "home"))
    res = subprocess.run(
        [sys.executable, "-m", "acet", "doctor", "--full", "--json"], capture_output=True, text=True, env=env
    )
    out = json.loads(res.stdout)
    return res.returncode, next(c for c in out["checks"] if c["name"] == "golden self-test")


def test_doctor_full_without_live_engines_is_never_reported_verified(tmp_path):
    """A skipped or replayed engine check must not make the self-test look complete (ACC-026)."""
    code, st = _doctor_full_subprocess(tmp_path, {})
    assert st["status"] == "WARN" and st["data"]["self_test"]["verdict"] == "PARTIAL"
    assert st["data"]["self_test"]["engine_mode"] == "none" and code == 10
    replay = Path(__file__).resolve().parents[2] / "datasets" / "demo" / "golden" / "ghidra"
    code, st = _doctor_full_subprocess(tmp_path, {"ACET_GHIDRA_REPLAY_DIR": str(replay)})
    assert st["status"] == "WARN" and st["data"]["self_test"]["engine_mode"] == "replay" and code == 10
    checks = {c["name"]: c["ok"] for c in st["data"]["self_test"]["checks"]}
    assert checks["STANDARD golden consensus"] is True and checks["golden Ghidra extraction"] is None
