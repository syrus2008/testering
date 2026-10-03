"""Release Evidence Bundle builder and release gate (spec §89, §119, ACET-REL-001, ACC-050/099/139).

    python tools/release_evidence.py build <out_dir> --artifacts dist/*.exe --sbom sbom.cdx.json \\
        --junit junit.xml [--security-scan scan.json] [--supplied release-inputs/<version>] \\
        [--key-file secret.hex | --key-env ACET_RELEASE_SIGNING_KEY] --key-id <id>
    python tools/release_evidence.py check <out_dir> --channel STABLE [--artifacts dist/*.exe] [--trust keys.json]

The gate validates *content*, never mere presence:

* the release manifest is signed with Ed25519 by a trusted, non-revoked ``release`` key and the
  signed payload is byte-for-byte the manifest; the manifest pins the SHA-256 of every evidence
  file, so nothing in the bundle can be swapped after signing;
* ``checksums.txt`` lists exactly the files of the bundle;
* every evidence file is checked against its own rules (SBOM structure and hash, test report
  derived from the real JUnit run, migration tests passed for the current schema, every
  automated acceptance criterion backed by passing tests, every manual criterion backed by an
  executed protocol result, clean-VM installs of *this* installer, a triaged vulnerability scan
  of *this* SBOM, a closed and approved license audit, benchmark gates recomputed against the
  committed baseline).

The tool never fabricates results: anything that cannot be produced by the pipeline (clean-VM
installs, manual protocols) must be supplied as result files by the release owner (``--supplied``).
BETA/DEVELOPER channels only enforce bundle integrity (signature when present, checksums).
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

CHANNELS = ("STABLE", "BETA", "DEVELOPER")
MANIFEST = "release-manifest.json"
SIGNATURE = "signatures/release-manifest.sig.json"
CHECKSUMS = "checksums.txt"
UNSIGNED = {MANIFEST, SIGNATURE, CHECKSUMS}  # everything else is pinned by the signed manifest
REQUIRED = [
    MANIFEST,
    SIGNATURE,
    "sbom/sbom.cdx.json",
    "licenses/license-audit.json",
    "licenses/license-audit.md",
    "compatibility-matrix.json",
    "test-report.json",
    "migration-test-report.json",
    "acceptance-matrix.json",
    "benchmark-summary.json",
    "golden-results/",
    "clean-vm-install-results/windows10.json",
    "clean-vm-install-results/windows11.json",
    "security-scan-summary.json",
    "known-limitations.json",
    CHECKSUMS,
]
CLEAN_VM = {"windows10.json": "10", "windows11.json": "11"}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
INTEGRITY = "[integrity] "


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _read_json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def _write_json(p: Path, data: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _iso(v: Any) -> bool:
    try:
        datetime.fromisoformat(str(v))
    except ValueError:
        return False
    return True


def _files(out: Path) -> list[str]:
    return sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())


# --------------------------------------------------------------------------- JUnit → reports
def nodeid_from_junit(classname: str, name: str) -> str:
    """``tests.ui.test_ui`` + ``test_x`` → ``tests/ui/test_ui.py::test_x`` (classes kept as ``::Cls``)."""
    parts = classname.split(".")
    for i in range(len(parts), 0, -1):
        if (ROOT / Path(*parts[:i])).with_suffix(".py").is_file():
            return "::".join([Path(*parts[:i]).as_posix() + ".py", *parts[i:], name])
    return "::".join([classname.replace(".", "/") + ".py", name])


def test_report_from_junit(junit: Path, commit: str) -> dict[str, Any]:
    tests: dict[str, str] = {}
    for tc in ET.parse(junit).getroot().iter("testcase"):
        tags = {child.tag for child in tc}
        outcome = "failed" if tags & {"failure", "error"} else "skipped" if "skipped" in tags else "passed"
        nid = nodeid_from_junit(tc.get("classname", ""), tc.get("name", ""))
        # Parametrized cases collapse onto the base test; any failing case fails it.
        base = nid.split("[", 1)[0]
        prev = tests.get(base)
        if prev is not None and prev != "passed" and outcome != "failed":
            continue
        tests[base] = outcome
    totals = {k: sum(1 for v in tests.values() if v == k) for k in ("passed", "failed", "skipped")}
    return {
        "status": "PASSED" if tests and not totals["failed"] else "FAILED",
        "commit": commit,
        "junit_sha256": _sha(junit),
        "totals": totals,
        "tests": tests,
    }


def migration_report(test_report: dict[str, Any]) -> dict[str, Any]:
    from acet.storage.migrations import LATEST_SCHEMA_VERSION

    mig = {k: v for k, v in test_report["tests"].items() if "migration" in k.split("::")[-1]}
    ok = len(mig) >= 2 and all(v == "passed" for v in mig.values())
    return {
        "status": "PASSED" if ok else "FAILED",
        "commit": test_report["commit"],
        "schema_version": LATEST_SCHEMA_VERSION,
        "tests": mig,
    }


# --------------------------------------------------------------------------- build
def build(
    out: Path,
    artifacts: list[Path],
    sbom: Path | None,
    *,
    junit: Path | None = None,
    security_scan: Path | None = None,
    supplied: Path | None = None,
    secret: bytes | None = None,
    key_id: str | None = None,
    baseline_dir: Path | None = None,
    license_audit: Path | None = None,
) -> dict[str, Any]:
    import acet
    from acet.benchmark.gates import check_gates
    from acet.platform.signing import sign_payload
    from tools import license_audit as lic

    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} is not empty: an evidence bundle is always built from scratch")
    out.mkdir(parents=True, exist_ok=True)
    commit = _git("rev-parse", "HEAD")

    (out / "licenses").mkdir()
    audit_src = license_audit or lic.AUDIT_JSON
    shutil.copyfile(audit_src, out / "licenses" / "license-audit.json")
    (out / "licenses" / "license-audit.md").write_text(lic.render(lic.load(audit_src)), encoding="utf-8")
    shutil.copyfile(ROOT / "src" / "acet" / "platform" / "compatibility-matrix.json", out / "compatibility-matrix.json")
    shutil.copyfile(ROOT / "docs" / "traceability" / "acceptance-matrix.json", out / "acceptance-matrix.json")
    shutil.copyfile(ROOT / "src" / "acet" / "engines" / "known_limitations.json", out / "known-limitations.json")

    (out / "golden-results").mkdir()
    bench: dict[str, Any] = {}
    for b in sorted((ROOT / "benchmarks").glob("*.json")):
        shutil.copyfile(b, out / "golden-results" / b.name)
        res = _read_json(b)
        base = (baseline_dir or ROOT / "benchmarks" / "baselines") / b.name
        bench[b.stem] = {
            "engines": res.get("engines"),
            "summary": res["summary"],
            "gates": check_gates(res["summary"], _read_json(base)) if base.is_file() else None,
        }
    _write_json(out / "benchmark-summary.json", bench)

    if sbom is not None:
        (out / "sbom").mkdir()
        shutil.copyfile(sbom, out / "sbom" / "sbom.cdx.json")
    if security_scan is not None:
        shutil.copyfile(security_scan, out / "security-scan-summary.json")
    if junit is not None:
        report = test_report_from_junit(junit, commit)
        _write_json(out / "test-report.json", report)
        _write_json(out / "migration-test-report.json", migration_report(report))
    # Results only a human can produce are copied verbatim from the release owner's inputs.
    if supplied is not None:
        for sub in ("clean-vm-install-results", "manual-acceptance"):
            if (supplied / sub).is_dir():
                shutil.copytree(supplied / sub, out / sub)

    manifest = {
        "acet_version": acet.__version__,
        "commit": commit,
        "tag": _git("describe", "--tags", "--always"),
        "build_id": os.environ.get("GITHUB_RUN_ID") or f"local-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
        "created_at": datetime.now(UTC).isoformat(),
        "artifacts": {a.name: _sha(a) for a in artifacts},
        "sbom_sha256": _sha(out / "sbom" / "sbom.cdx.json") if sbom is not None else None,
        "evidence": {rel: _sha(out / rel) for rel in _files(out) if rel not in UNSIGNED},
    }
    _write_json(out / MANIFEST, manifest)
    if secret is not None:
        if not key_id:
            raise SystemExit("--key-id is required with a signing key")
        _write_json(out / SIGNATURE, sign_payload(manifest, secret, key_id))
    lines = [f"{_sha(out / rel)}  {rel}" for rel in _files(out) if rel != CHECKSUMS]
    (out / CHECKSUMS).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


# --------------------------------------------------------------------------- check
class _Gate:
    def __init__(self, out: Path) -> None:
        self.out = out
        self.problems: list[str] = []

    def integrity(self, msg: str) -> None:
        self.problems.append(INTEGRITY + msg)

    def evidence(self, msg: str) -> None:
        self.problems.append(msg)

    def json(self, rel: str, *, integrity: bool = False) -> Any:
        p = self.out / rel
        if not p.is_file():
            return None
        try:
            return _read_json(p)
        except ValueError:
            (self.integrity if integrity else self.evidence)(f"invalid JSON: {rel}")
            return None


def _check_checksums(g: _Gate) -> None:
    path = g.out / CHECKSUMS
    if not path.is_file():
        g.integrity(f"missing: {CHECKSUMS}")
        return
    listed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        sha, sep, rel = line.partition("  ")
        if not sep or not SHA_RE.match(sha):
            g.integrity(f"malformed checksum line: {line!r}")
            continue
        listed[rel] = sha
    actual = {rel for rel in _files(g.out) if rel != CHECKSUMS}
    for rel in sorted(actual - listed.keys()):
        g.integrity(f"file not covered by checksums.txt: {rel}")
    for rel, sha in sorted(listed.items()):
        p = g.out / rel
        if not p.is_file():
            g.integrity(f"checksum lists a missing file: {rel}")
        elif _sha(p) != sha:
            g.integrity(f"checksum mismatch: {rel}")


def _check_signature(g: _Gate, manifest: dict[str, Any] | None, trust_file: Path | None, required: bool) -> bool:
    from acet.domain.error_codes import AcetError
    from acet.platform.signing import load_trust_store, verify_envelope

    env = g.json(SIGNATURE, integrity=True)
    if env is None:
        if required:
            g.integrity(f"missing or unreadable: {SIGNATURE}")
        return False
    if manifest is None:
        g.integrity("signature present but release-manifest.json is missing or invalid")
        return False
    try:
        payload = verify_envelope(env, load_trust_store(trust_file), purpose="release")
    except AcetError as exc:
        g.integrity(f"release manifest signature invalid: {exc.detail}")
        return False
    if payload != manifest:
        g.integrity("signed payload differs from release-manifest.json")
        return False
    return True


def _check_manifest(g: _Gate, m: dict[str, Any], artifacts: list[Path]) -> None:
    import acet

    if not COMMIT_RE.match(str(m.get("commit"))):
        g.evidence(f"manifest: commit is not a full git SHA: {m.get('commit')!r}")
    if m.get("acet_version") != acet.__version__:
        g.evidence(f"manifest: acet_version {m.get('acet_version')!r} != checked-out {acet.__version__!r}")
    if not _iso(m.get("created_at")):
        g.evidence("manifest: created_at is not an ISO timestamp")
    arts = m.get("artifacts")
    if not isinstance(arts, dict) or not arts or not all(SHA_RE.match(str(v)) for v in arts.values()):
        g.evidence("manifest: no released artifacts with SHA-256")
    for a in artifacts:
        if not a.is_file():
            g.integrity(f"artifact not found: {a}")
        elif (arts or {}).get(a.name) != _sha(a):
            g.integrity(f"artifact {a.name} does not match the signed manifest")
    ev = m.get("evidence")
    if not isinstance(ev, dict):
        g.integrity("manifest: no evidence hashes")
        return
    present = {rel for rel in _files(g.out) if rel not in UNSIGNED}
    for rel in sorted(present - ev.keys()):
        g.integrity(f"evidence file not pinned by the signed manifest: {rel}")
    for rel, sha in sorted(ev.items()):
        p = g.out / rel
        if not p.is_file():
            g.integrity(f"evidence pinned by the manifest is missing: {rel}")
        elif _sha(p) != sha:
            g.integrity(f"evidence modified after signing: {rel}")


def _check_sbom(g: _Gate, m: dict[str, Any]) -> None:
    sb = g.json("sbom/sbom.cdx.json")
    if sb is None:
        return
    if sb.get("bomFormat") != "CycloneDX" or not str(sb.get("specVersion", "")).startswith("1."):
        g.evidence("sbom: not a CycloneDX 1.x document")
    comps = sb.get("components")
    if not isinstance(comps, list) or not comps or not all(c.get("name") and c.get("version") for c in comps):
        g.evidence("sbom: components missing or without name/version")
    if (sb.get("metadata") or {}).get("component", {}).get("name") != "acet":
        g.evidence("sbom: metadata.component is not acet")
    if m.get("sbom_sha256") != _sha(g.out / "sbom" / "sbom.cdx.json"):
        g.evidence("sbom: hash differs from the manifest")


def _check_tests(g: _Gate, m: dict[str, Any]) -> dict[str, str]:
    from acet.storage.migrations import LATEST_SCHEMA_VERSION

    tr = g.json("test-report.json")
    tests: dict[str, str] = {}
    if tr is not None:
        tests = tr.get("tests") if isinstance(tr.get("tests"), dict) else {}
        if not tests:
            g.evidence("test-report: no test results")
        failed = sorted(k for k, v in tests.items() if v not in ("passed", "skipped"))
        if failed:
            g.evidence(f"test-report: {len(failed)} failed test(s), e.g. {failed[:3]}")
        if tr.get("status") != "PASSED":
            g.evidence(f"test-report: status {tr.get('status')!r}")
        if tr.get("commit") != m.get("commit"):
            g.evidence("test-report: produced for another commit")
    mr = g.json("migration-test-report.json")
    if mr is not None:
        mig = mr.get("tests") if isinstance(mr.get("tests"), dict) else {}
        if mr.get("status") != "PASSED" or len(mig) < 2 or any(v != "passed" for v in mig.values()):
            g.evidence(f"migration-test-report: status {mr.get('status')!r}, tests {mig}")
        if mr.get("schema_version") != LATEST_SCHEMA_VERSION:
            g.evidence(f"migration-test-report: schema {mr.get('schema_version')} != {LATEST_SCHEMA_VERSION}")
        if mr.get("commit") != m.get("commit"):
            g.evidence("migration-test-report: produced for another commit")
        for k, v in mig.items():
            if tests.get(k) != v:
                g.evidence(f"migration-test-report: {k} not confirmed by test-report")
    return tests


def _check_acceptance(g: _Gate, m: dict[str, Any], tests: dict[str, str]) -> None:
    acc = g.json("acceptance-matrix.json")
    if acc is None:
        return
    crit = acc.get("criteria")
    if not isinstance(crit, list) or len(crit) < 150:
        g.evidence(f"acceptance-matrix: expected 150 criteria, got {len(crit) if isinstance(crit, list) else 0}")
        return
    artifacts = set((m.get("artifacts") or {}).values())
    for c in crit:
        cid, status = c.get("id"), c.get("status")
        if status == "automated":
            ids = c.get("tests") or []
            if not ids:
                g.evidence(f"{cid}: automated without tests")
            for t in ids:
                if tests.get(t) != "passed":
                    g.evidence(f"{cid}: test {t} is {tests.get(t, 'absent')} in test-report")
        elif status == "manual_protocol":
            proto = c.get("manual_protocol") or {}
            r = g.json(f"manual-acceptance/{cid}.json")
            if r is None:
                g.evidence(f"{cid}: manual protocol {proto.get('protocol')} has no executed result")
                continue
            _check_executed(g, f"{cid} ({proto.get('protocol')})", r, m, artifacts)
            if r.get("protocol") != proto.get("protocol") or r.get("protocol_version") != proto.get("version"):
                g.evidence(f"{cid}: result is for protocol {r.get('protocol')}@{r.get('protocol_version')}")
        else:
            g.evidence(f"{cid}: status {status!r}")


def _check_executed(g: _Gate, what: str, r: dict[str, Any], m: dict[str, Any], artifacts: set[str]) -> None:
    """Common rules for a result a human produced on a real machine."""
    if r.get("status") != "PASSED":
        g.evidence(f"{what}: status {r.get('status')!r}")
    if not str(r.get("executor") or "").strip():
        g.evidence(f"{what}: no executor")
    if not _iso(r.get("executed_at")):
        g.evidence(f"{what}: executed_at missing or invalid")
    elif str(r["executed_at"]) < str(m.get("created_at", ""))[:10]:
        g.evidence(f"{what}: executed before this release was built")
    if r.get("installer_sha256") not in artifacts:
        g.evidence(f"{what}: installer_sha256 is not an artifact of this release")
    if r.get("acet_version") != m.get("acet_version"):
        g.evidence(f"{what}: acet_version {r.get('acet_version')!r} != {m.get('acet_version')!r}")
    checks = r.get("checks")
    if not isinstance(checks, list) or not checks:
        g.evidence(f"{what}: no individual checks recorded")
    else:
        bad = [c.get("name") for c in checks if not c.get("name") or c.get("result") != "PASSED"]
        if bad:
            g.evidence(f"{what}: checks not passed: {bad}")


def _check_clean_vm(g: _Gate, m: dict[str, Any]) -> None:
    artifacts = set((m.get("artifacts") or {}).values())
    for name, version in CLEAN_VM.items():
        r = g.json(f"clean-vm-install-results/{name}")
        if r is None:
            continue
        what = f"clean-vm-install-results/{name}"
        _check_executed(g, what, r, m, artifacts)
        os_ = r.get("os") or {}
        if os_.get("name") != "Windows" or str(os_.get("version")) != version or not os_.get("build"):
            g.evidence(f"{what}: os must be Windows {version} with a build number, got {os_}")
        if r.get("clean_vm") is not True:
            g.evidence(f"{what}: not declared as a clean VM")


def _check_security(g: _Gate, m: dict[str, Any]) -> None:
    s = g.json("security-scan-summary.json")
    if s is None:
        return
    if s.get("status") != "PASSED" or s.get("untriaged"):
        g.evidence(f"security-scan: status {s.get('status')!r}, untriaged {s.get('untriaged')}")
    if s.get("sbom_sha256") != m.get("sbom_sha256"):
        g.evidence("security-scan: not run on this release's SBOM")
    if not isinstance(s.get("components"), int) or s["components"] < 1:
        g.evidence("security-scan: scanned no components")
    if (
        not isinstance(s.get("advisories"), int)
        or s["advisories"] < 1
        or not SHA_RE.match(str(s.get("advisories_sha256")))
    ):
        g.evidence("security-scan: no identified advisory database")
    if not _iso(s.get("scanned_at")):
        g.evidence("security-scan: scanned_at missing")
    for f in s.get("findings") or []:
        t = f.get("triage") or {}
        if not t.get("decision") or not t.get("rationale"):
            g.evidence(f"security-scan: finding {f.get('id')} triage lacks decision/rationale")


def _check_licenses(g: _Gate) -> None:
    from tools import license_audit

    a = g.json("licenses/license-audit.json")
    if a is None:
        return
    for p in license_audit.problems(a):
        g.evidence(p)
    md = g.out / "licenses" / "license-audit.md"
    if md.is_file() and md.read_text(encoding="utf-8") != license_audit.render(a):
        g.evidence("license-audit.md does not match license-audit.json")


def _check_benchmarks(g: _Gate, baseline_dir: Path) -> None:
    from acet.benchmark.gates import check_gates

    b = g.json("benchmark-summary.json")
    if b is None:
        return
    if not isinstance(b, dict) or not b:
        g.evidence("benchmark-summary: empty")
        return
    live = [k for k, v in b.items() if str(v.get("engines", "")).startswith("live:")]
    if not live:
        g.evidence("benchmark-summary: no benchmark with live engines (replay is never release evidence)")
    for name, v in b.items():
        base = baseline_dir / f"{name}.json"
        golden = g.json(f"golden-results/{name}.json")
        if golden is None or golden.get("summary") != v.get("summary"):
            g.evidence(f"benchmark-summary: {name} does not match golden-results/{name}.json")
        if not base.is_file():
            g.evidence(f"benchmark-summary: {name} has no committed baseline")
            continue
        failed = [x["gate"] for x in check_gates(v.get("summary") or {}, _read_json(base)) if not x["ok"]]
        if failed:
            g.evidence(f"benchmark {name}: regression gates failed: {failed}")


def _check_registries(g: _Gate) -> None:
    c = g.json("compatibility-matrix.json")
    if c is not None:
        provs = c.get("providers")
        # A provider ACET does not ship (external-*) may list no validated version.
        if (
            not isinstance(provs, list)
            or not provs
            or not all(
                p.get("provider_id")
                and p.get("status")
                and isinstance(p.get("versions"), list)
                and (p["versions"] or str(p["status"]).startswith("external"))
                for p in provs
            )
        ):
            g.evidence("compatibility-matrix: providers missing or incomplete")
    k = g.json("known-limitations.json")
    if k is not None:
        lims = k.get("limitations")
        if not isinstance(k.get("registry_version"), int) or not isinstance(lims, list):
            g.evidence("known-limitations: not a registry")
        elif not all(x.get("id") and x.get("status") and x.get("provider_id") for x in lims):
            g.evidence("known-limitations: entries without id/status/provider_id")


def check(
    out: Path,
    channel: str = "STABLE",
    *,
    artifacts: list[Path] | None = None,
    trust_file: Path | None = None,
    baseline_dir: Path | None = None,
) -> list[str]:
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel {channel!r}")
    g = _Gate(out)
    stable = channel == "STABLE"
    _check_checksums(g)
    manifest = g.json(MANIFEST, integrity=True)
    if not isinstance(manifest, dict):
        g.integrity(f"missing or invalid: {MANIFEST}")
        manifest = None
    signed = _check_signature(g, manifest, trust_file, required=stable)
    if manifest is not None:
        _check_manifest(g, manifest, artifacts or [])
    if stable:
        if not signed:
            g.evidence("STABLE requires a manifest signed by a trusted release key")
        for item in REQUIRED:
            p = out / item
            if item.endswith("/") and (not p.is_dir() or not any(p.iterdir())):
                g.evidence(f"missing or empty: {item}")
            elif not item.endswith("/") and not p.is_file():
                g.evidence(f"missing: {item}")
        m = manifest or {}
        _check_sbom(g, m)
        tests = _check_tests(g, m)
        _check_acceptance(g, m, tests)
        _check_clean_vm(g, m)
        _check_security(g, m)
        _check_licenses(g)
        _check_benchmarks(g, baseline_dir or ROOT / "benchmarks" / "baselines")
        _check_registries(g)
    problems = list(dict.fromkeys(g.problems))
    return problems if stable else [p for p in problems if p.startswith(INTEGRITY)]


# --------------------------------------------------------------------------- CLI
def _expand(patterns: list[str]) -> list[Path]:
    out: list[Path] = []
    for pat in patterns:
        hits = sorted(glob.glob(pat)) or [pat]
        out += [Path(h) for h in hits]
    return out


def _secret(args: argparse.Namespace) -> bytes | None:
    raw = None
    if args.key_file:
        raw = args.key_file.read_text(encoding="ascii")
    elif args.key_env:
        raw = os.environ.get(args.key_env)
        if not raw:
            raise SystemExit(f"environment variable {args.key_env} is empty")
    if raw is None:
        return None
    try:
        secret = bytes.fromhex(raw.strip())
    except ValueError as exc:
        raise SystemExit("signing key is not hex") from exc
    if len(secret) != 32:
        raise SystemExit("signing key must be a 32-byte Ed25519 seed")
    return secret


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="release_evidence.py", description="Build or check an ACET Release Evidence Bundle."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="assemble (and sign) a new evidence bundle")
    b.add_argument("out_dir", type=Path)
    b.add_argument("--artifacts", nargs="+", default=[], metavar="FILE", help="released files (globs allowed)")
    b.add_argument("--sbom", type=Path)
    b.add_argument("--junit", type=Path, help="JUnit XML of the full pytest run of this commit")
    b.add_argument("--security-scan", type=Path, help="output of tools/vuln_scan.py")
    b.add_argument(
        "--supplied", type=Path, help="release-owner results (clean-vm-install-results/, manual-acceptance/)"
    )
    k = b.add_mutually_exclusive_group()
    k.add_argument("--key-file", type=Path, help="hex Ed25519 seed (keep outside the repository)")
    k.add_argument("--key-env", metavar="VAR", help="environment variable holding the hex Ed25519 seed")
    b.add_argument("--key-id")
    c = sub.add_parser("check", help="run the release gate on a bundle")
    c.add_argument("out_dir", type=Path)
    c.add_argument("--channel", choices=CHANNELS, default="STABLE")
    c.add_argument("--artifacts", nargs="+", default=[], metavar="FILE", help="verify these files against the manifest")
    c.add_argument("--trust", type=Path, help="additional trusted_keys.json")
    args = ap.parse_args(argv)

    if args.cmd == "build":
        arts = _expand(args.artifacts)
        missing = [a for a in arts if not a.is_file()]
        if missing:
            ap.error(f"artifacts not found: {', '.join(map(str, missing))}")
        for opt in ("sbom", "junit", "security_scan", "supplied"):
            p = getattr(args, opt)
            if p is not None and not p.exists():
                ap.error(f"--{opt.replace('_', '-')}: {p} not found")
        secret = _secret(args)
        if secret is not None and not args.key_id:
            ap.error("--key-id is required with --key-file/--key-env")
        build(
            args.out_dir,
            arts,
            args.sbom,
            junit=args.junit,
            security_scan=args.security_scan,
            supplied=args.supplied,
            secret=secret,
            key_id=args.key_id,
        )
        print(f"evidence bundle written to {args.out_dir}" + ("" if secret else " (UNSIGNED)"))
        return 0
    probs = check(args.out_dir, args.channel, artifacts=_expand(args.artifacts), trust_file=args.trust)
    print("\n".join(probs) or f"release evidence complete for {args.channel}")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
