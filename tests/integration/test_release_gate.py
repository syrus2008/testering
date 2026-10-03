"""Release gate: evidence is validated for content and provenance, never accepted for mere presence."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import quoteattr

import pytest

import acet
from acet.platform import ed25519

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import license_audit, release_evidence, vuln_scan  # noqa: E402
from tools.sbom import build_sbom  # noqa: E402

SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 test key
OTHER = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
MATRIX = json.loads((ROOT / "docs" / "traceability" / "acceptance-matrix.json").read_text(encoding="utf-8"))
MIGRATION_TESTS = [
    "tests/integration/test_storage.py::test_every_migration_step_applies_in_sequence",
    "tests/integration/test_storage.py::test_migration_failure_rolls_back_atomically",
]


@pytest.fixture
def trust(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Release keys are only trusted from the bundled store of the reviewed source tree."""
    from acet.platform import signing

    key = {"key_id": "rel", "alg": "ed25519", "public_key": ed25519.public_key(SECRET).hex(), "purposes": ["release"]}
    store = {"keys": [key]}
    monkeypatch.setattr(signing, "_bundled_store", lambda: store)
    return store


def _junit(path: Path, outcomes: dict[str, str]) -> Path:
    cases = []
    for nodeid, outcome in outcomes.items():
        file, *rest = nodeid.split("::")
        classname = ".".join([file[:-3].replace("/", "."), *rest[:-1]])
        body = {"passed": "", "failed": "<failure message='x'/>", "skipped": "<skipped message='x'/>"}[outcome]
        cases.append(f"<testcase classname={quoteattr(classname)} name={quoteattr(rest[-1])}>{body}</testcase>")
    path.write_text(f"<testsuites><testsuite name='pytest'>{''.join(cases)}</testsuite></testsuites>")
    return path


def _all_tests_passing() -> dict[str, str]:
    tests = {t: "passed" for c in MATRIX["criteria"] for t in c.get("tests", [])}
    tests.update({t: "passed" for t in MIGRATION_TESTS})
    return tests


def _executed(installer_sha: str, **extra: object) -> dict[str, object]:
    return {
        "status": "PASSED",
        "executor": "Release Owner",
        "executed_at": datetime.now(UTC).isoformat(),
        "installer_sha256": installer_sha,
        "acet_version": acet.__version__,
        "checks": [{"name": "installer completes", "result": "PASSED"}, {"name": "app starts", "result": "PASSED"}],
        **extra,
    }


def _approved_audit(tmp_path: Path) -> Path:
    a = license_audit.load()
    for c in a["components"]:
        c["status"] = "CLOSED"
        c["how_satisfied"] = "EULA shipped as packaging/EULA.txt" if c["component"] == "ACET" else c["how_satisfied"]
    a["approval"] = {"status": "APPROVED", "approved_by": "Legal Reviewer", "approved_at": "2026-10-01", "note": ""}
    p = tmp_path / "license-audit.json"
    p.write_text(json.dumps(a))
    return p


@pytest.fixture
def inputs(tmp_path: Path) -> dict[str, object]:
    installer = tmp_path / "ACET-Setup-1.0.exe"
    installer.write_bytes(b"installer bytes")
    sha = release_evidence._sha(installer)
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(build_sbom()))
    adv = tmp_path / "advisories.json"
    adv.write_text(json.dumps([{"id": "OSV-X", "package": "nothing-we-ship", "affected_versions": ["1"]}]))
    scan = tmp_path / "scan.json"
    assert vuln_scan.main([str(sbom), str(adv), str(scan)]) == 0
    supplied = tmp_path / "supplied"
    for name, ver in release_evidence.CLEAN_VM.items():
        r = _executed(sha, os={"name": "Windows", "version": ver, "build": "26100.1"}, clean_vm=True)
        release_evidence._write_json(supplied / "clean-vm-install-results" / name, r)
    for c in MATRIX["criteria"]:
        if c["status"] == "manual_protocol":
            mp = c["manual_protocol"]
            r = _executed(sha, protocol=mp["protocol"], protocol_version=mp["version"])
            release_evidence._write_json(supplied / "manual-acceptance" / f"{c['id']}.json", r)
    return {
        "installer": installer,
        "sbom": sbom,
        "scan": scan,
        "supplied": supplied,
        "junit": _junit(tmp_path / "junit.xml", _all_tests_passing()),
        "audit": _approved_audit(tmp_path),
    }


def _build(out: Path, i: dict[str, object], *, secret: bytes | None = SECRET, **over: object) -> dict[str, object]:
    kw: dict[str, object] = {
        "junit": i["junit"],
        "security_scan": i["scan"],
        "supplied": i["supplied"],
        "secret": secret,
        "key_id": "rel",
        "license_audit": i["audit"],
    }
    kw.update(over)
    return release_evidence.build(out, [i["installer"]], i["sbom"], **kw)  # type: ignore[arg-type]


def _reseal_checksums(out: Path) -> None:
    lines = [f"{release_evidence._sha(out / r)}  {r}" for r in release_evidence._files(out) if r != "checksums.txt"]
    (out / "checksums.txt").write_text("\n".join(lines) + "\n")


@pytest.mark.acceptance("ACC-099", "ACC-139")
def _stable_platform(tmp_path, monkeypatch):
    """The build being released: official distribution channel, no development key."""
    d = tmp_path / "platform"
    d.mkdir()
    keys = json.loads((release_evidence.PLATFORM_DIR / "trusted_keys.json").read_text(encoding="utf-8"))
    keys["keys"] = [k for k in keys["keys"] if k.get("channel") != "dev"]
    (d / "trusted_keys.json").write_text(json.dumps(keys), encoding="utf-8")
    (d / "distribution.json").write_text(json.dumps({"channel": "stable", "index_urls": []}), encoding="utf-8")
    monkeypatch.setattr(release_evidence, "PLATFORM_DIR", d)


def test_complete_signed_bundle_passes_stable(tmp_path, trust, inputs, monkeypatch):
    out = tmp_path / "evidence"
    _build(out, inputs)
    assert any("development key" in p for p in release_evidence.check(out, "STABLE", artifacts=[inputs["installer"]]))
    _stable_platform(tmp_path, monkeypatch)
    assert release_evidence.check(out, "STABLE", artifacts=[inputs["installer"]]) == []


def test_auditor_fake_evidence_is_rejected(tmp_path, trust):
    """Audit repro: placeholder files, a '{}' signature, an open license audit and a doctored
    acceptance summary must not pass STABLE."""
    out = tmp_path / "evidence"
    for item in release_evidence.REQUIRED:
        p = out / item
        if item.endswith("/"):
            p.mkdir(parents=True, exist_ok=True)
            (p / "x.json").write_text("{}")
        elif item.endswith(".json"):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}")
    (out / "licenses" / "license-audit.md").write_text("INCOMPLETE TO AUDIT")
    (out / "acceptance-matrix.json").write_text(json.dumps({"summary": {"not_started": 0, "partial": 0}}))
    _reseal_checksums(out)
    problems = release_evidence.check(out, "STABLE")
    text = "\n".join(problems)
    assert "release manifest signature invalid" in text
    assert "STABLE requires a manifest signed by a trusted release key" in text
    assert "acceptance-matrix: expected 150 criteria" in text
    assert "license audit: no components" in text
    assert "sbom: not a CycloneDX" in text
    assert "test-report: no test results" in text
    assert "security-scan" in text and "clean-vm-install-results/windows11.json: status None" in text


def test_unsigned_or_foreign_signature_is_refused(tmp_path, trust, inputs):
    out = tmp_path / "unsigned"
    _build(out, inputs, secret=None)
    assert any("signed by a trusted release key" in p for p in release_evidence.check(out, "STABLE"))
    out2 = tmp_path / "foreign"
    _build(out2, inputs, secret=OTHER)
    assert any("signature invalid" in p for p in release_evidence.check(out2, "STABLE"))
    assert any("signature invalid" in p for p in release_evidence.check(out2, "BETA"))


def test_tampering_after_signing_is_detected(tmp_path, trust, inputs):
    out = tmp_path / "evidence"
    _build(out, inputs)
    r = json.loads((out / "clean-vm-install-results" / "windows11.json").read_text())
    r["status"] = "PASSED"
    r["executor"] = "someone else"
    (out / "clean-vm-install-results" / "windows11.json").write_text(json.dumps(r))
    _reseal_checksums(out)  # an attacker can recompute checksums.txt, not the signature
    assert any("evidence modified after signing" in p for p in release_evidence.check(out, "BETA"))
    # Editing the manifest itself breaks the signature.
    m = json.loads((out / "release-manifest.json").read_text())
    m["evidence"]["clean-vm-install-results/windows11.json"] = release_evidence._sha(
        out / "clean-vm-install-results" / "windows11.json"
    )
    (out / "release-manifest.json").write_text(json.dumps(m))
    _reseal_checksums(out)
    assert any("signed payload differs" in p for p in release_evidence.check(out, "STABLE"))
    # Extra unlisted file.
    (out / "extra.json").write_text("{}")
    assert any("not covered by checksums.txt: extra.json" in p for p in release_evidence.check(out, "BETA"))


def test_artifact_must_match_signed_manifest(tmp_path, trust, inputs):
    out = tmp_path / "evidence"
    _build(out, inputs)
    inputs["installer"].write_bytes(b"swapped installer")  # type: ignore[union-attr]
    assert any(
        "does not match the signed manifest" in p
        for p in release_evidence.check(out, "BETA", artifacts=[inputs["installer"]])
    )


def test_open_license_audit_blocks_stable(tmp_path, trust, inputs):
    out = tmp_path / "evidence"
    _build(out, inputs, license_audit=license_audit.AUDIT_JSON)  # the repository audit is not approved yet
    problems = release_evidence.check(out, "STABLE")
    assert any("approval status 'PENDING'" in p for p in problems)
    assert any("license audit: ACET: status 'OPEN'" in p for p in problems)


def test_license_audit_rejects_undecided_wording():
    a = license_audit.load()
    a["components"][1]["how_satisfied"] = "to audit at packaging"
    assert any("undecided wording" in p for p in license_audit.problems(a))


def test_failing_or_missing_tests_block_acceptance(tmp_path, trust, inputs):
    outcomes = _all_tests_passing()
    victim = next(c for c in MATRIX["criteria"] if c["status"] == "automated")
    outcomes[victim["tests"][0]] = "skipped"
    outcomes[MIGRATION_TESTS[1]] = "failed"
    out = tmp_path / "evidence"
    _build(out, inputs, junit=_junit(tmp_path / "j2.xml", outcomes))
    text = "\n".join(release_evidence.check(out, "STABLE"))
    assert f"{victim['id']}: test {victim['tests'][0]} is skipped" in text
    assert "migration-test-report: status 'FAILED'" in text
    assert "test-report: 1 failed test(s)" in text


def test_manual_and_clean_vm_results_must_concern_this_installer(tmp_path, trust, inputs):
    supplied: Path = inputs["supplied"]  # type: ignore[assignment]
    manual = sorted((supplied / "manual-acceptance").glob("*.json"))
    manual[0].unlink()
    w10 = supplied / "clean-vm-install-results" / "windows10.json"
    r = json.loads(w10.read_text())
    r["installer_sha256"] = "0" * 64
    r["os"]["version"] = "11"
    w10.write_text(json.dumps(r))
    out = tmp_path / "evidence"
    _build(out, inputs)
    text = "\n".join(release_evidence.check(out, "STABLE"))
    assert f"{manual[0].stem}: manual protocol" in text and "has no executed result" in text
    assert "windows10.json: installer_sha256 is not an artifact of this release" in text
    assert "windows10.json: os must be Windows 10" in text


def test_cli_help_and_argument_errors(tmp_path):
    tool = [sys.executable, str(ROOT / "tools" / "release_evidence.py")]
    for args in ([], ["build"], ["check"]):
        res = subprocess.run([*tool, *args, "--help"], capture_output=True, text=True)
        assert res.returncode == 0 and "usage:" in res.stdout, res.stderr
    res = subprocess.run(
        [*tool, "build", str(tmp_path / "o"), "--artifacts", str(tmp_path / "nope.exe")], capture_output=True, text=True
    )
    assert res.returncode == 2 and "artifacts not found" in res.stderr
    res = subprocess.run([*tool, "check", str(tmp_path / "o"), "--channel", "NIGHTLY"], capture_output=True, text=True)
    assert res.returncode == 2
    res = subprocess.run([*tool, "check", str(tmp_path / "empty")], capture_output=True, text=True)
    assert res.returncode == 1 and "missing" in res.stdout


def test_license_audit_markdown_is_generated_from_json():
    assert license_audit.AUDIT_MD.read_text(encoding="utf-8") == license_audit.render(license_audit.load())
