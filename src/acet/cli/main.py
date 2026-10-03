"""``acet`` command line (spec §53).

Exit codes: 0 success · 10 partial success · 20 user error · 30 analysis failure · 40 system failure.
Errors print a stable code, a summary, the data impact and a recommended action;
stack traces only with ``--debug`` ("Developer details").
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import acet
from acet.domain.enums import ComponentRole, FailureFamily, SystemHealth
from acet.domain.error_codes import AcetError, classify_exception

EXIT_OK = 0
EXIT_PARTIAL = 10
EXIT_USER = 20
EXIT_ANALYSIS = 30
EXIT_SYSTEM = 40

_USER_FAMILIES = {
    FailureFamily.INPUT,
    FailureFamily.FORMAT,
    FailureFamily.CONFIGURATION,
    FailureFamily.SECURITY,
    FailureFamily.COMPATIBILITY,
    FailureFamily.CANCELLATION,
}
_ANALYSIS_FAMILIES = {FailureFamily.ENGINE, FailureFamily.TIMEOUT, FailureFamily.PROTOCOL}


def exit_code_for(err: AcetError) -> int:
    if err.family in _USER_FAMILIES:
        return EXIT_USER
    if err.family in _ANALYSIS_FAMILIES:
        return EXIT_ANALYSIS
    return EXIT_SYSTEM


def _emit(args: argparse.Namespace, payload: Any, text: str) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    else:
        print(text)


def _resolve_workspace(args: argparse.Namespace) -> Path:
    from acet.platform.paths import workspaces_root

    ref = args.workspace or os.environ.get("ACET_WORKSPACE")
    if ref:
        p = Path(ref)
        if p.is_dir():
            return p
        candidate = workspaces_root() / ref
        if candidate.is_dir():
            return candidate
        raise AcetError("ACET-WS-001", f"workspace {ref!r} not found")
    root = workspaces_root()
    found = [d for d in root.iterdir() if (d / "acet.db").is_file()] if root.is_dir() else []
    if len(found) == 1:
        return found[0]
    raise AcetError(
        "ACET-WS-001", "pass --workspace (or set ACET_WORKSPACE)" + (f"; {len(found)} found" if found else "")
    )


def _open(args: argparse.Namespace, *, read_only: bool = False):  # type: ignore[no-untyped-def]
    from acet.application.workspace import open_workspace

    return open_workspace(_resolve_workspace(args), read_only=read_only)


# -- commands --------------------------------------------------------------
def cmd_workspace_create(args: argparse.Namespace) -> int:
    from acet.application.workspace import create_workspace

    ws = create_workspace(args.name, Path(args.root) if args.root else None)
    with ws:
        _emit(args, {"id": ws.id, "name": ws.name, "path": str(ws.path)}, f"workspace {ws.id} created at {ws.path}")
    return EXIT_OK


def cmd_workspace_list(args: argparse.Namespace) -> int:
    from acet.platform.paths import workspaces_root

    root = Path(args.root) if args.root else workspaces_root()
    items = []
    if root.is_dir():
        for d in sorted(root.iterdir()):
            meta = d / "workspace.json"
            if meta.is_file():
                items.append({**json.loads(meta.read_text(encoding="utf-8")), "path": str(d)})
    _emit(args, items, "\n".join(f"{i['id']}  {i['name']}" for i in items) or "(no workspaces)")
    return EXIT_OK


def cmd_product_create(args: argparse.Namespace) -> int:
    from acet.application.products import create_product

    profile = json.loads(Path(args.profile).read_text(encoding="utf-8")) if args.profile else None
    with _open(args) as ws:
        pid = create_product(ws, args.name, vendor=args.vendor, profile=profile)
    _emit(args, {"id": pid, "name": args.name}, f"product {pid} created")
    return EXIT_OK


def cmd_product_list(args: argparse.Namespace) -> int:
    from acet.application.products import list_products

    with _open(args, read_only=True) as ws:
        items = list_products(ws)
    _emit(args, items, "\n".join(f"{p['id']}  {p['name']}" for p in items) or "(no products)")
    return EXIT_OK


def cmd_import(args: argparse.Namespace) -> int:
    from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build

    overrides: dict[str, ComponentRole] = {}
    for spec in args.role or []:
        name, _, role = spec.rpartition("=")
        if not name:
            raise AcetError("ACET-IMP-005", f"--role expects NAME=ROLE, got {spec!r}")
        try:
            overrides[name] = ComponentRole(role.upper())
        except ValueError:
            raise AcetError("ACET-IMP-005", f"unknown role {role!r}") from None
    req = ImportRequest(
        paths=[Path(p) for p in args.paths],
        product=args.product,
        release_label=args.release,
        channel=args.channel,
        observed_at=args.observed_at,
        source_label=args.source_label,
        on_duplicate=DuplicatePolicy(args.on_duplicate),
        role_overrides=overrides,
    )
    with _open(args) as ws:
        res = import_build(ws, req)
    verb = "created build" if res.created_build else "added observation to existing build"
    lines = [
        f"{verb} {res.build_id}",
        f"  fingerprint {res.build_fingerprint}",
        f"  status {res.status.value}; new artifacts {len(res.new_artifacts)}, reused {len(res.reused_artifacts)}",
        *(f"  {f['role']:<14} {f['role_confidence']:<7} {f['sha256'][:16]}…  {f['name']}" for f in res.files),
        *(f"  warning: {w}" for w in res.warnings),
    ]
    _emit(args, res.to_dict(), "\n".join(lines))
    return EXIT_OK


def cmd_builds_list(args: argparse.Namespace) -> int:
    from acet.application.builds import list_builds

    with _open(args, read_only=True) as ws:
        items = list_builds(ws, args.product, include_deleted=args.all)
    _emit(
        args,
        items,
        "\n".join(
            f"{b['id']}  {b['status']:<10} {b['version_label'] or '-':<12} obs={b['observations']}"
            f"{'  [trash]' if b['deleted_at'] else ''}"
            for b in items
        )
        or "(no builds)",
    )
    return EXIT_OK


def cmd_builds_show(args: argparse.Namespace) -> int:
    from acet.application.builds import get_build

    with _open(args, read_only=True) as ws:
        b = get_build(ws, args.build_id)
    text = [f"build {b['id']} [{b['status']}]", f"  fingerprint {b['build_fingerprint']}"]
    text += [
        f"  {c['role']:<14} {c['sha256'][:16]}…  {c['label'] or ''}  [{c['integrity_state']}]" for c in b["components"]
    ]
    _emit(args, b, "\n".join(text))
    return EXIT_OK


def cmd_builds_verify(args: argparse.Namespace) -> int:
    from acet.application.builds import verify_build_artifacts

    with _open(args) as ws:
        shas = verify_build_artifacts(ws, args.build_id)
    _emit(args, {"verified": shas}, f"{len(shas)} artifact(s) verified")
    return EXIT_OK


def cmd_builds_delete(args: argparse.Namespace) -> int:
    from acet.application.builds import soft_delete_build

    with _open(args) as ws:
        soft_delete_build(ws, args.build_id)
    _emit(args, {"trashed": args.build_id}, f"build {args.build_id} moved to trash (recoverable)")
    return EXIT_OK


def cmd_builds_restore(args: argparse.Namespace) -> int:
    from acet.application.builds import restore_build

    with _open(args) as ws:
        restore_build(ws, args.build_id)
    _emit(args, {"restored": args.build_id}, f"build {args.build_id} restored")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    from acet.platform.doctor import overall_health, system_checks, workspace_checks

    checks = system_checks()
    ws_ref = args.workspace or os.environ.get("ACET_WORKSPACE")
    if ws_ref:
        with _open(args, read_only=True) as ws:
            wchecks, _ = workspace_checks(ws, full=args.full)
        checks += wchecks
    health = overall_health(checks)
    payload = {"health": health.value, "checks": [c.to_dict() for c in checks]}
    text = [f"ACET {acet.__version__} — {health.value}"]
    text += [f"  [{c.status.value:<13}] {c.name}: {c.detail}" for c in checks]
    _emit(args, payload, "\n".join(text))
    if health is SystemHealth.ACTION_REQUIRED:
        return EXIT_SYSTEM
    return EXIT_PARTIAL if health is SystemHealth.DEGRADED else EXIT_OK


def cmd_reconcile(args: argparse.Namespace) -> int:
    from acet.platform.doctor import quarantine_orphans, reconcile

    with _open(args, read_only=not args.quarantine_orphans) as ws:
        rep = reconcile(ws, deep=args.deep)
        moved = quarantine_orphans(ws, rep) if args.quarantine_orphans else 0
    payload = {**rep.to_dict(), "quarantined": moved}
    _emit(args, payload, json.dumps(payload, indent=2))
    return EXIT_OK if rep.clean else EXIT_SYSTEM


def cmd_backup(args: argparse.Namespace) -> int:
    from acet.domain.timeutil import utc_now_iso

    with _open(args, read_only=True) as ws:
        stamp = utc_now_iso().replace(":", "").replace("-", "").replace(".", "")
        dest = Path(args.dest) if args.dest else ws.path / "backups" / f"metadata-{stamp}.db"
        ws.db.backup_to(dest)
    _emit(args, {"backup": str(dest)}, f"metadata backup written: {dest}")
    return EXIT_OK


def _run_exit(status: str) -> int:
    return {
        "COMPLETED": EXIT_OK,
        "COMPLETED_PARTIAL": EXIT_PARTIAL,
        "CANCELLED": EXIT_PARTIAL,
        "RUNNING": EXIT_PARTIAL,
    }.get(status, EXIT_ANALYSIS)


def _print_run(args: argparse.Namespace, s: Any) -> int:
    d = s.to_dict()
    lines = [f"run {d['run_id']} {d['status']} coverage={d['coverage']} cache_hits={d['cache_hits']}"]
    lines += [f"  missing: {m['processor']} {m['outcome']} — {m['reason']}" for m in d["missing_evidence"]]
    lines += [f"  warning: {w}" for w in d["warnings"]]
    _emit(args, d, "\n".join(lines))
    return _run_exit(d["status"])


def cmd_analyze(args: argparse.Namespace) -> int:
    from acet.analysis.orchestrator import analyze_build

    with _open(args) as ws:
        return _print_run(args, analyze_build(ws, args.build_id, args.profile))


def cmd_compare(args: argparse.Namespace) -> int:
    from acet.analysis.orchestrator import compare_builds

    with _open(args) as ws:
        return _print_run(args, compare_builds(ws, args.left, args.right, args.profile))


def cmd_lineage(args: argparse.Namespace) -> int:
    from acet.lineage.builder import build_lineage

    with _open(args) as ws:
        prod = _product_id(ws, args.product)
        res = build_lineage(ws, prod, incremental=not args.full)
    _emit(args, res.to_dict(), json.dumps(res.to_dict(), indent=2))
    return EXIT_PARTIAL if res.missing_pairs else EXIT_OK


def _product_id(ws: Any, ref: str) -> str:
    from acet.storage import repositories as repo

    p = repo.find_product(ws.db.conn, ref)
    if p is None:
        raise AcetError("ACET-NOTFOUND-001", f"product {ref!r}")
    return str(p["id"])


def cmd_runs_list(args: argparse.Namespace) -> int:
    with _open(args, read_only=True) as ws:
        rows = [
            dict(r)
            for r in ws.db.conn.execute(
                "SELECT id, scope_type, scope_id, status, coverage, started_at, finished_at FROM analysis_run ORDER BY seq"
            )
        ]
    _emit(
        args,
        rows,
        "\n".join(f"{r['id']}  {r['scope_type']:<8} {r['status']:<18} cov={r['coverage']}" for r in rows)
        or "(no runs)",
    )
    return EXIT_OK


def cmd_runs_show(args: argparse.Namespace) -> int:
    with _open(args, read_only=True) as ws:
        run = ws.db.conn.execute("SELECT * FROM analysis_run WHERE id=?", (args.run_id,)).fetchone()
        if run is None:
            raise AcetError("ACET-NOTFOUND-001", f"run {args.run_id}")
        d = dict(run)
        d["processor_runs"] = [
            dict(r)
            for r in ws.db.conn.execute(
                "SELECT processor_id, processor_version, status, outcome, cache_hit, cache_key, input_hash, config_hash,"
                " termination, completion_state, error_code FROM processor_run WHERE analysis_run_id=? ORDER BY rowid",
                (args.run_id,),
            )
        ]
    for k in ("resolved_config_json", "missing_evidence_json", "coverage_json", "warnings_json", "input_hashes_json"):
        if d.get(k):
            d[k[:-5]] = json.loads(d.pop(k))
    _emit(args, d, json.dumps(d, indent=2, default=str))
    return EXIT_OK


def cmd_jobs_list(args: argparse.Namespace) -> int:
    from acet.jobs import store as jobs

    with _open(args) as ws:
        recovered = jobs.recover_interrupted(ws.db)
        items = jobs.list_jobs(ws.db, active_only=not args.all)
    text = "\n".join(
        f"{j['id']}  {j['job_type']:<9} {j['state']:<16} {j['stage'] or '':<24} {j['progress']}" for j in items
    )
    if recovered:
        text += f"\n{len(recovered)} interrupted job(s) can be resumed: acet jobs resume <id>"
    _emit(args, {"jobs": items, "recovered": recovered}, text or "(no jobs)")
    return EXIT_OK


def cmd_jobs_resume(args: argparse.Namespace) -> int:
    from acet.analysis.orchestrator import resume
    from acet.jobs import store as jobs

    with _open(args) as ws:
        jobs.recover_interrupted(ws.db)
        return _print_run(args, resume(ws, args.job_id))


def cmd_jobs_cancel(args: argparse.Namespace) -> int:
    from acet.jobs import store as jobs

    with _open(args) as ws:
        jobs.request(ws.db, args.job_id, "cancel")
        state = jobs.get_job(ws.db, args.job_id)["state"]  # type: ignore[index]
    _emit(args, {"job_id": args.job_id, "state": state}, f"job {args.job_id}: {state}")
    return EXIT_OK


def cmd_jobs_pause(args: argparse.Namespace) -> int:
    from acet.jobs import store as jobs

    with _open(args) as ws:
        jobs.request(ws.db, args.job_id, "pause")
    _emit(args, {"job_id": args.job_id, "state": "PAUSING"}, f"job {args.job_id}: pause requested")
    return EXIT_OK


def cmd_changes(args: argparse.Namespace) -> int:
    from acet.changes.detector import detect_changes, list_changes

    with _open(args) as ws:
        exists = ws.db.conn.execute(
            "SELECT 1 FROM detected_change WHERE analysis_run_id=? LIMIT 1", (args.run_id,)
        ).fetchone()
        if not exists:
            detect_changes(ws, args.run_id)
        items = list_changes(ws, args.run_id)
    lines = [
        f"{c['component_role']:<14} {c['dimension']:<22} state={c['measurement_state']:<14} "
        f"severity={c['severity_class']:<8} reliability={c['reliability_class']}"
        for c in items
    ]
    lines.append("(dimensions are reported separately; ACET computes no global score)")
    _emit(args, items, "\n".join(lines))
    return EXIT_OK


def cmd_events_add(args: argparse.Namespace) -> int:
    from acet.changes.events import add_event

    with _open(args) as ws:
        eid = add_event(
            ws,
            _product_id(ws, args.product),
            event_type=args.type,
            summary=args.summary,
            source_class=args.source_class,
            occurred_at=args.occurred_at,
            source_ref=args.source_ref,
            corroboration=args.corroboration,
        )
    _emit(args, {"id": eid}, f"external event {eid} recorded")
    return EXIT_OK


def cmd_timeline(args: argparse.Namespace) -> int:
    from acet.changes.timeline import product_timeline

    with _open(args, read_only=True) as ws:
        items = product_timeline(ws, _product_id(ws, args.product))
    _emit(
        args,
        items,
        "\n".join(
            f"{i['at'] or '?':<22} {i['kind']:<15} "
            + (i.get("release") or i.get("event_type") or i.get("status") or "")
            for i in items
        ),
    )
    return EXIT_OK


def cmd_benchmark_run(args: argparse.Namespace) -> int:
    from acet.benchmark.gates import check_gates
    from acet.benchmark.runner import run_benchmark

    with _open(args) as ws:
        res = run_benchmark(ws, Path(args.dataset), args.profile, split=args.split)
    code = EXIT_OK
    if args.baseline:
        gates = check_gates(res["summary"], json.loads(Path(args.baseline).read_text(encoding="utf-8")))
        res["gates"] = gates
        code = EXIT_OK if all(g["ok"] for g in gates) else EXIT_ANALYSIS
    _emit(args, res, json.dumps({"summary": res["summary"], "gates": res.get("gates")}, indent=2))
    return code


def cmd_benchmark_calibrate(args: argparse.Namespace) -> int:
    from acet.benchmark.calibration import calibrate

    with _open(args) as ws:
        ids = calibrate(ws, args.benchmark_run_id, args.engine)
    _emit(args, {"calibration_profiles": ids}, f"{len(ids)} calibration profile(s) (validated only if n>=30)")
    return EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    from acet.reporting.model import compare_report
    from acet.reporting.render import write_report

    with _open(args, read_only=True) as ws:
        rep = compare_report(ws, args.run_id, include_sensitive=args.include_sensitive)
        dest = Path(args.output) if args.output else ws.path / "reports" / f"{args.run_id}.{args.format}"
    write_report(rep, args.format, dest)
    _emit(args, {"report": str(dest)}, f"report written: {dest}")
    return EXIT_OK


def cmd_pack_create(args: argparse.Namespace) -> int:
    from acet.reporting.acetpack import create_pack

    with _open(args) as ws:
        dest = create_pack(ws, Path(args.output), include_artifacts=args.include_artifacts)
    _emit(args, {"pack": str(dest)}, f"pack written: {dest}")
    return EXIT_OK


def cmd_pack_import(args: argparse.Namespace) -> int:
    from acet.reporting.acetpack import import_pack

    with _open(args) as ws:
        res = import_pack(ws, Path(args.pack))
    _emit(args, res, json.dumps(res, indent=2))
    return EXIT_OK


def cmd_diagnostics(args: argparse.Namespace) -> int:
    from acet.platform.diagnostics import create_diagnostic_package

    ws_ref = args.workspace or os.environ.get("ACET_WORKSPACE")
    if ws_ref:
        with _open(args, read_only=True) as ws:
            dest = create_diagnostic_package(ws, Path(args.output))
    else:
        dest = create_diagnostic_package(None, Path(args.output))
    _emit(args, {"package": str(dest)}, f"diagnostic package: {dest} (no artifacts, paths sanitized)")
    return EXIT_OK


def cmd_restore(args: argparse.Namespace) -> int:
    from acet.application.backup import restore_metadata

    ws = _open(args)
    restored = restore_metadata(ws, Path(args.backup))
    restored.close()
    _emit(args, {"restored": args.backup}, "metadata restored (integrity verified before swap)")
    return EXIT_OK


def cmd_cleanup(args: argparse.Namespace) -> int:
    from acet.platform.retention import apply_cleanup, plan_cleanup

    with _open(args, read_only=not args.apply) as ws:
        plan = plan_cleanup(ws)
        freed = apply_cleanup(ws, plan) if args.apply else 0
    d = {**plan.to_dict(), "applied": args.apply, "freed_bytes": freed}
    lines = [f"  {i.category:<10} {i.bytes:>12}  {i.path}  ({i.reason})" for i in plan.items]
    lines.append(f"{'freed' if args.apply else 'dry run — would free'} {plan.total_bytes} bytes")
    _emit(args, d, "\n".join(lines))
    return EXIT_OK


def cmd_purge(args: argparse.Namespace) -> int:
    from acet.platform.retention import apply_purge, plan_purge

    with _open(args, read_only=not args.apply) as ws:
        plan = apply_purge(ws, args.build_id) if args.apply else plan_purge(ws, args.build_id)
    _emit(args, {**plan, "applied": args.apply}, json.dumps({**plan, "applied": args.apply}, indent=2))
    return EXIT_OK


def cmd_annotate(args: argparse.Namespace) -> int:
    from acet.application.annotations import add_annotation

    with _open(args) as ws:
        aid = add_annotation(ws, args.target_type, args.target_id, args.body)
    _emit(args, {"id": aid}, f"annotation {aid}")
    return EXIT_OK


def cmd_search(args: argparse.Namespace) -> int:
    from acet.application.search import search

    with _open(args, read_only=True) as ws:
        hits = search(ws, args.query)
    _emit(args, hits, "\n".join(f"{h['kind']:<10} {h['id'][:36]:<38} {h['title']}" for h in hits) or "(no match)")
    return EXIT_OK


def cmd_settings(args: argparse.Namespace) -> int:
    from acet.application.settings import effective_settings, set_setting

    with _open(args, read_only=args.value is None) as ws:
        if args.key and args.value is not None:
            set_setting(ws, args.key, json.loads(args.value))
        cur = effective_settings(ws)
    _emit(args, cur, "\n".join(f"{k} = {json.dumps(v)}" for k, v in cur.items()))
    return EXIT_OK


def _not_yet(phase: str):  # type: ignore[no-untyped-def]
    def run(args: argparse.Namespace) -> int:
        _emit(args, {"error": "not implemented", "roadmap_phase": phase}, f"not implemented yet (roadmap {phase})")
        return EXIT_USER

    return run


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--workspace", "-w", help="workspace directory or id (or ACET_WORKSPACE)")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument("--debug", action="store_true", help="show developer details on error")

    p = argparse.ArgumentParser(prog="acet", parents=[common], description="ACET — Anti-Cheat Evolution Tracker")
    p.add_argument("--version", action="version", version=f"acet {acet.__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", parents=[common], help="diagnose system and workspace")
    d.add_argument("--full", action="store_true", help="full integrity check and blob re-hash")
    d.set_defaults(func=cmd_doctor)

    w = sub.add_parser("workspace", help="workspace management").add_subparsers(dest="sub", required=True)
    wc = w.add_parser("create", parents=[common])
    wc.add_argument("name")
    wc.add_argument("--root", help="parent directory (default: %%LOCALAPPDATA%%\\ACET\\workspaces)")
    wc.set_defaults(func=cmd_workspace_create)
    wl = w.add_parser("list", parents=[common])
    wl.add_argument("--root")
    wl.set_defaults(func=cmd_workspace_list)

    pr = sub.add_parser("product", help="products").add_subparsers(dest="sub", required=True)
    pc = pr.add_parser("create", parents=[common])
    pc.add_argument("name")
    pc.add_argument("--vendor")
    pc.add_argument("--profile", help="Product Profile v2 JSON file (declarative only)")
    pc.set_defaults(func=cmd_product_create)
    pr.add_parser("list", parents=[common]).set_defaults(func=cmd_product_list)

    im = sub.add_parser("import", parents=[common], help="import files/folders as one build")
    im.add_argument("paths", nargs="+")
    im.add_argument("--product", required=True, help="product id or exact name")
    im.add_argument("--release", help="release version label")
    im.add_argument("--channel")
    im.add_argument("--observed-at", help="YYYY[-MM[-DD]] or ISO-8601 datetime with timezone")
    im.add_argument("--source-label", help="short provenance label (no full paths stored)")
    im.add_argument("--on-duplicate", choices=["cancel", "add-observation"], default="cancel")
    im.add_argument("--role", action="append", metavar="NAME=ROLE", help="override proposed role for a file name")
    im.set_defaults(func=cmd_import)

    b = sub.add_parser("builds", help="builds").add_subparsers(dest="sub", required=True)
    bl = b.add_parser("list", parents=[common])
    bl.add_argument("--product")
    bl.add_argument("--all", action="store_true", help="include trashed builds")
    bl.set_defaults(func=cmd_builds_list)
    for name, fn in (
        ("show", cmd_builds_show),
        ("verify", cmd_builds_verify),
        ("delete", cmd_builds_delete),
        ("restore", cmd_builds_restore),
    ):
        bp = b.add_parser(name, parents=[common])
        bp.add_argument("build_id")
        bp.set_defaults(func=fn)

    rc = sub.add_parser("reconcile", parents=[common], help="DB ↔ artifact store consistency")
    rc.add_argument("--deep", action="store_true", help="re-hash every blob")
    rc.add_argument("--quarantine-orphans", action="store_true", help="move orphan blobs to quarantine")
    rc.set_defaults(func=cmd_reconcile)

    bk = sub.add_parser("backup", parents=[common], help="WAL-aware metadata backup")
    bk.add_argument("--dest")
    bk.set_defaults(func=cmd_backup)

    for name, phase in (
        ("analyze", "P4/P5"),
        ("compare", "P6"),
        ("benchmark", "P10"),
        ("jobs", "P3"),
        ("export", "P11"),
        ("pack", "P11"),
    ):
        sp = sub.add_parser(name, parents=[common], help=f"(roadmap {phase})")
        sp.add_argument("rest", nargs=argparse.REMAINDER)
        sp.set_defaults(func=_not_yet(phase))
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code == 0 else EXIT_USER
    try:
        return int(args.func(args))
    except Exception as exc:  # ACET-CLOSE-002: every failure is mapped
        err = classify_exception(exc)
        if args.json:
            print(json.dumps({"error": err.to_dict()}, indent=2, ensure_ascii=False), file=sys.stderr)
        else:
            print(f"error {err.code}: {err.spec.summary}" + (f" — {err.detail}" if err.detail else ""), file=sys.stderr)
            print(f"  impact: {err.spec.impact}", file=sys.stderr)
            print(f"  action: {err.spec.action}", file=sys.stderr)
            if err.data:
                print(f"  data:   {json.dumps(err.data, ensure_ascii=False)}", file=sys.stderr)
            print("  diagnostics: acet doctor --full", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return exit_code_for(err)


if __name__ == "__main__":
    raise SystemExit(main())
