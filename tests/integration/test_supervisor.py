"""Process supervision (spec §60, ACET-JOB-003, ACET-ENG-001, ACC-051/052/053/087/143)."""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

from acet.jobs.completion import CompletionState, LogRule, validate_completion
from acet.jobs.locks import pid_alive
from acet.jobs.supervisor import Limits, Termination, run_supervised


def _script(tmp_path: Path, body: str) -> list[str]:
    p = tmp_path / "s.py"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return [sys.executable, str(p)]


@pytest.mark.acceptance("ACC-052")
def test_process_tree_is_killed_on_hard_timeout(tmp_path):
    pids = tmp_path / "pids.txt"
    # Each level is a script file (no nested quoting: Windows paths contain backslashes).
    grandchild = tmp_path / "grandchild.py"
    grandchild.write_text(
        f"import os, time\nopen({str(pids)!r}, 'a').write(str(os.getpid()) + '\\n')\ntime.sleep(120)\n",
        encoding="utf-8",
    )
    child = tmp_path / "child.py"
    child.write_text(
        f"import os, subprocess, sys, time\nopen({str(pids)!r}, 'a').write(str(os.getpid()) + '\\n')\n"
        f"subprocess.Popen([sys.executable, {str(grandchild)!r}])\ntime.sleep(120)\n",
        encoding="utf-8",
    )
    argv = _script(
        tmp_path,
        f"""
        import subprocess, sys, time
        subprocess.Popen([sys.executable, {str(child)!r}])
        time.sleep(120)
    """,
    )
    res = run_supervised(
        argv, workdir=tmp_path / "w", log_dir=tmp_path / "logs", limits=Limits(hard_timeout_s=3, grace_s=1)
    )
    assert res.termination is Termination.TIMEOUT
    assert res.stop_method in ("killpg_sigkill", "terminate_job_object")
    time.sleep(0.5)
    found = [int(x) for x in pids.read_text().split()] if pids.exists() else []
    assert len(found) == 2, "child and grandchild should have started"
    assert not any(pid_alive(p) for p in found), "no descendant may survive (ACC-052)"


def test_heartbeat_loss_marks_hung(tmp_path):
    argv = _script(tmp_path, "import time\ntime.sleep(60)\n")
    res = run_supervised(
        argv,
        workdir=tmp_path / "w",
        log_dir=tmp_path / "logs",
        limits=Limits(heartbeat_timeout_s=1.0, hard_timeout_s=30, grace_s=1),
        heartbeat_file=tmp_path / "w" / ".hb",
    )
    assert res.hung and res.termination is Termination.TIMEOUT
    assert res.wall_ms < 20000


@pytest.mark.acceptance("ACC-087")
def test_logs_are_bounded(tmp_path):
    argv = _script(
        tmp_path,
        """
        import sys
        for i in range(200000):
            sys.stdout.write(f"line {i} " + "x" * 40 + (" ERROR boom" if i % 1000 == 0 else "") + "\\n")
    """,
    )
    res = run_supervised(
        argv,
        workdir=tmp_path / "w",
        log_dir=tmp_path / "logs",
        limits=Limits(log_head_bytes=32 * 1024, log_tail_bytes=32 * 1024),
    )
    assert res.termination is Termination.NORMAL and res.exit_code == 0
    assert res.stdout.total_bytes > 8_000_000
    assert res.stdout.truncated
    assert res.stdout.error_lines == 200  # counters survive truncation
    assert res.stdout_path.stat().st_size < 100 * 1024


def _write_manifest(out: Path, **over) -> None:
    (out / "result.json").write_text("{}", encoding="utf-8")
    import hashlib

    sha = hashlib.sha256(b"{}").hexdigest()
    m = {
        "protocol_version": 1,
        "provider_id": "t",
        "provider_version": "1",
        "run_id": "01a10000-0000-7000-8000-000000000000",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "termination": "normal",
        "engine_exit_code": 0,
        "engine_reported_errors": 0,
        "engine_reported_warnings": 0,
        "expected_outputs": ["result.json"],
        "present_outputs": ["result.json"],
        "output_checksums": {"result.json": sha},
        "analysis_counts": {},
        "completion_state": "complete",
    }
    m.update(over)
    (out / "completion-manifest.json").write_text(json.dumps(m), encoding="utf-8")


def _ok_proc(tmp_path: Path, text: str = "fine\n"):
    argv = _script(tmp_path, f"print({text!r}, end='')\n")
    return run_supervised(argv, workdir=tmp_path / "w", log_dir=tmp_path / "logs")


@pytest.mark.acceptance("ACC-051", "ACC-143")
def test_exit_zero_without_valid_outputs_is_never_completed(tmp_path):
    proc = _ok_proc(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    assert validate_completion(proc, out, expected_outputs=["result.json"]).state is CompletionState.INVALID
    _write_manifest(out)
    assert validate_completion(proc, out, expected_outputs=["result.json"]).state is CompletionState.COMPLETE
    (out / "result.json").write_text('{"tampered": 1}', encoding="utf-8")
    v = validate_completion(proc, out, expected_outputs=["result.json"])
    assert v.state is CompletionState.INVALID and any("checksum" in r for r in v.reasons)
    _write_manifest(out, completion_state="partial", present_outputs=[])
    assert validate_completion(proc, out, expected_outputs=["result.json"]).state is CompletionState.PARTIAL
    (out / "completion-manifest.json").write_text('{"protocol_version": 1}', encoding="utf-8")
    assert validate_completion(proc, out, expected_outputs=["result.json"]).state is CompletionState.INVALID


@pytest.mark.acceptance("ACC-053")
def test_engine_internal_error_in_logs_degrades_run(tmp_path):
    proc = _ok_proc(tmp_path, "INFO start\nERROR Analysis failed for function X\nINFO done\n")
    out = tmp_path / "out"
    out.mkdir()
    _write_manifest(out)
    from acet.engines.quirks import log_rules_for

    v = validate_completion(proc, out, expected_outputs=["result.json"], log_rules=log_rules_for("ghidra"))
    assert v.state is CompletionState.PARTIAL and "GHD-LOG-001" in v.matched_rules
    rule = LogRule("X", r"never-matches", CompletionState.INVALID, "x")
    assert (
        validate_completion(proc, out, expected_outputs=["result.json"], log_rules=[rule]).state
        is CompletionState.COMPLETE
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_crash_is_classified(tmp_path):
    argv = _script(tmp_path, "import os, signal\nos.kill(os.getpid(), signal.SIGSEGV)\n")
    res = run_supervised(argv, workdir=tmp_path / "w", log_dir=tmp_path / "logs")
    assert res.termination is Termination.CRASH


def test_minimal_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ACET_SECRET_TOKEN_FIXTURE", "s3cr3t")
    argv = _script(tmp_path, "import os\nprint(os.environ.get('ACET_SECRET_TOKEN_FIXTURE', 'absent'))\n")
    res = run_supervised(argv, workdir=tmp_path / "w", log_dir=tmp_path / "logs")
    assert "absent" in res.stdout_path.read_text() and os.environ["ACET_SECRET_TOKEN_FIXTURE"] == "s3cr3t"
