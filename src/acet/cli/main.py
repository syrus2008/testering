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
