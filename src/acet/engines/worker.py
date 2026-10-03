"""Generic worker process (protocol v1, spec §52).

Invoked by the Supervisor as ``python -m acet.engines.worker <request.json>``.
The processor to run is resolved from ACET's own registry by id/version — a
request can never name arbitrary code. The worker writes ``result.json``,
``response.json`` and ``completion-manifest.json`` atomically into its output
directory and touches ``.heartbeat`` every second.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acet.domain.canonical import stable_json

PROTOCOL_VERSION = 1


@dataclass(frozen=True)
class InputRef:
    kind: str
    sha256: str
    path: Path


class ProcessorSkip(Exception):
    """Raised by a processor that refuses cleanly (memory gate, known limitation, policy)."""

    def __init__(self, status: str, reason: str, code: str | None = None) -> None:
        super().__init__(reason)
        self.status, self.reason, self.code = status, reason, code


class WorkerContext:
    def __init__(self, request: dict[str, Any], output_dir: Path) -> None:
        self.request = request
        self.config: dict[str, Any] = request["config"]
        self.output_dir = output_dir
        self.inputs = [InputRef(i["kind"], i["sha256"], Path(i["path"])) for i in request["inputs"]]
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.counts: dict[str, int] = {}
        self.extra_outputs: list[str] = []
        self.engine_version: str | None = None
        self.termination = "normal"  # set by adapters that observe an engine-native timeout (ACET-GHD-005)
        self._hb = output_dir / ".heartbeat"
        # Engine adapters switch this off and beat on real engine activity, so a hung
        # engine behind a live wrapper is still detected (ACET-JOB-003).
        self.auto_heartbeat = True

    # inputs
    def artifact_path(self, i: int) -> Path:
        return [x for x in self.inputs if x.kind == "artifact"][i].path

    def derived(self, i: int) -> Any:
        ref = [x for x in self.inputs if x.kind == "derived"][i]
        return json.loads(ref.path.read_text(encoding="utf-8"))

    def layout(self) -> dict[str, Any]:
        return dict(self.config.get("_layout", {}))

    # signals
    def heartbeat(self) -> None:
        self._hb.touch()

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        print(f"WARNING {msg}", flush=True)

    def error(self, msg: str) -> None:
        self.errors.append(msg)
        print(f"ERROR {msg}", flush=True)

    def count(self, key: str, n: int) -> None:
        self.counts[key] = self.counts.get(key, 0) + int(n)

    def skip(self, status: str, reason: str, code: str | None = None) -> None:
        """status: SKIPPED_POLICY | SKIPPED_INCOMPATIBLE | SKIPPED_KNOWN_LIMITATION."""
        raise ProcessorSkip(status, reason, code)

    def derived_dir(self, i: int) -> Path:
        return [x for x in self.inputs if x.kind == "derived"][i].path.parent

    def stop_requested(self) -> bool:
        return (self.output_dir / ".stop").exists()

    def write_output(self, name: str, data: bytes) -> Path:
        p = self.output_dir / name
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)
        if name not in self.extra_outputs:
            self.extra_outputs.append(name)
        return p


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _atomic_json(p: Path, obj: Any, canonical: bool = False) -> None:
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_bytes(stable_json(obj) if canonical else json.dumps(obj, indent=2).encode())
    os.replace(tmp, p)


def _utc() -> str:
    from acet.domain.timeutil import utc_now_iso

    return utc_now_iso()


def _forbid_network() -> None:
    """§61: analysis workers have no network unless a capability explicitly needs it (ACC-003/078)."""
    import socket

    def refuse(*_a: object, **_k: object) -> None:
        raise PermissionError("network access is disabled for ACET analysis workers (ACET-SEC-002)")

    socket.socket.connect = refuse  # type: ignore[method-assign]
    socket.socket.connect_ex = refuse  # type: ignore[method-assign,assignment]
    socket.create_connection = refuse  # type: ignore[assignment]
    socket.getaddrinfo = refuse  # type: ignore[assignment]


def main(argv: list[str]) -> int:
    from acet.analysis.registry import resolve_entry
    from acet.domain.jsonschema import validate_named

    if os.environ.get("ACET_NO_NETWORK") == "1":
        _forbid_network()
    corr = os.environ.get("ACET_CORRELATION")
    if corr:
        print(f"ACET correlation: {corr}", flush=True)  # ACET-OBS-001: incident traceable UI→job→processor→logs

    req_path = Path(argv[0])
    request = json.loads(req_path.read_text(encoding="utf-8"))
    validate_named(request, "worker-request")
    out = Path(request["output_dir"])
    out.mkdir(parents=True, exist_ok=True)
    ctx = WorkerContext(request, out)
    stop = threading.Event()

    def beat() -> None:
        while not stop.wait(1.0):
            if ctx.auto_heartbeat:
                ctx.heartbeat()

    threading.Thread(target=beat, daemon=True).start()
    ctx.heartbeat()
    started = _utc()
    t0 = time.monotonic()
    status, termination = "success", "normal"
    result: Any = None
    try:
        fn = resolve_entry(request["processor"]["id"], request["processor"]["version"])
        result = fn(ctx)
    except ProcessorSkip as skip:
        result = {"skipped": skip.status, "reason": skip.reason, "code": skip.code}
        ctx.warn(f"{skip.status}: {skip.reason}")
    except Exception as exc:  # mapped to failed + structured error; never silently complete
        status = "failed"
        ctx.error(f"{type(exc).__name__}: {exc}")
        traceback.print_exc()
    finally:
        stop.set()
    present: list[str] = []
    checksums: dict[str, str] = {}
    if result is not None:
        _atomic_json(out / "result.json", result, canonical=True)
    for name in ["result.json", *ctx.extra_outputs]:
        p = out / name
        if p.is_file():
            present.append(name)
            checksums[name] = _sha(p)
    expected = ["result.json", *ctx.extra_outputs]
    if status != "failed" and ctx.errors:
        status = "partial"
    completion = (
        "complete"
        if status == "success" and set(expected) <= set(present)
        else ("partial" if status == "partial" else "invalid")
    )
    response = {
        "protocol_version": PROTOCOL_VERSION,
        "job_id": request["job_id"],
        "status": status,
        "facts": [],
        "results": present,
        "warnings": ctx.warnings,
        "metrics": {"wall_ms": int((time.monotonic() - t0) * 1000), "peak_rss_bytes": None},
        "artifacts": ctx.extra_outputs,
    }
    _atomic_json(out / "response.json", response)
    manifest = {
        "protocol_version": PROTOCOL_VERSION,
        "provider_id": request["processor"]["id"],
        "provider_version": ctx.engine_version or request["processor"]["version"],
        "run_id": request["job_id"],
        "started_at": started,
        "finished_at": _utc(),
        "termination": ctx.termination if termination == "normal" else termination,
        "engine_exit_code": 0,
        "engine_reported_errors": len(ctx.errors),
        "engine_reported_warnings": len(ctx.warnings),
        "expected_outputs": expected,
        "present_outputs": present,
        "output_checksums": checksums,
        "analysis_counts": ctx.counts,
        "completion_state": completion,
    }
    _atomic_json(out / "completion-manifest.json", manifest)
    return 0 if status != "failed" else 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
