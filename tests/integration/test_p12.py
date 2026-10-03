"""Engine Packs, signatures, updates, release evidence (P12)."""

from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

from acet.domain.error_codes import AcetError
from acet.platform import ed25519, engine_packs, updates
from acet.platform.signing import sign_payload, verify_envelope

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import release_evidence  # noqa: E402
from tools.build_engine_pack import build as build_pack  # noqa: E402
from tools.sbom import build_sbom  # noqa: E402

SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 test key


@pytest.fixture
def trust(monkeypatch):
    """Update and release keys can only come from the bundled store (ADR-0011)."""
    from acet.platform import signing

    key = {
        "key_id": "test",
        "alg": "ed25519",
        "public_key": ed25519.public_key(SECRET).hex(),
        "purposes": ["engine-pack", "update", "release"],
    }
    store = {"keys": [key]}
    monkeypatch.setattr(signing, "_bundled_store", lambda: store)
    return store


def test_ed25519_rfc8032_vectors():
    pk = ed25519.public_key(SECRET)
    assert pk.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = ed25519.sign(SECRET, b"")
    assert sig.hex().startswith("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac")
    assert ed25519.verify(pk, b"", sig) and not ed25519.verify(pk, b"x", sig)
    assert not ed25519.verify(pk, b"", sig[:-1] + bytes([sig[-1] ^ 1]))


def _config(tmp_path: Path, version: str = "1.0.0") -> dict:
    tool = tmp_path / f"fake-tool-{version}.txt"
    tool.write_text(f"provider payload {version}")
    return {
        "id": "test-pack",
        "version": version,
        "supported_acet": ">=0.1,<2.0",
        "sources": {"tool/run.txt": str(tool)},
        "providers": [
            {
                "provider_id": "bindiff",
                "provider_version": "8",
                "protocol_version": 1,
                "capabilities": ["STRUCTURAL_DIFF"],
                "executable": "tool/run.txt",
                "license_mode": "bundled",
                "health_check": "n/a",
                "supported_formats": ["PE32+"],
                "supported_architectures": ["x64"],
            }
        ],
        "licenses": [
            {
                "component": "bindiff",
                "spdx": "Apache-2.0",
                "redistribution": "yes",
                "bundling": "bundled",
                "version_audited": "8",
            }
        ],
    }


@pytest.mark.acceptance("ACC-057", "ACC-058", "ACC-061", "ACC-034", "ACC-127")
def test_engine_pack_verify_tamper_and_coexistence(tmp_path, trust):
    p1 = build_pack(_config(tmp_path, "1.0.0"), tmp_path / "pack1", SECRET, "test")
    p2 = build_pack(_config(tmp_path, "1.1.0"), tmp_path / "pack2", SECRET, "test")
    assert engine_packs.verify_pack(p1)["version"] == "1.0.0"
    tampered = tmp_path / "tampered"
    shutil.copytree(p1, tampered)
    (tampered / "tool" / "run.txt").write_text("malicious")
    with pytest.raises(AcetError) as ei:
        engine_packs.verify_pack(tampered)
    assert "tampered" in str(ei.value)
    forged = json.loads((p1 / "engine-pack.json").read_text())
    forged["payload"]["version"] = "9.9.9"
    (tampered / "engine-pack.json").write_text(json.dumps(forged))
    with pytest.raises(AcetError):
        engine_packs.verify_pack(tampered)  # signature no longer matches
    engine_packs.install_pack(p1)
    engine_packs.install_pack(p2)
    assert {p["version"] for p in engine_packs.installed_packs()} == {"1.0.0", "1.1.0"}
    assert engine_packs.resolve_pinned("test-pack@1.0.0")["version"] == "1.0.0"  # old pack still usable
    unlicensed = _config(tmp_path, "2.0.0")
    unlicensed["licenses"] = []
    with pytest.raises(AcetError):
        engine_packs.verify_pack(build_pack(unlicensed, tmp_path / "p3", SECRET, "test"))


@pytest.mark.acceptance("ACC-086")
def test_incompatible_protocol_refused(tmp_path, trust):
    cfg = _config(tmp_path)
    p = build_pack(cfg, tmp_path / "p", SECRET, "test")
    env = json.loads((p / "engine-pack.json").read_text())
    env["payload"]["protocol_version"] = 2
    env = sign_payload(env["payload"], SECRET, "test")
    (p / "engine-pack.json").write_text(json.dumps(env))
    with pytest.raises(AcetError):
        engine_packs.verify_pack(p)


def _bundle(tmp_path: Path, version: str, *, revoked: list | None = None, tamper: bool = False) -> Path:
    import hashlib

    payload = {"bin/acet.txt": f"ACET {version}".encode()}
    manifest = {
        "schema_version": 1,
        "version": version,
        "channel": "STABLE",
        "compatible_from": ">=0.1",
        "files": {k: hashlib.sha256(v).hexdigest() for k, v in payload.items()},
        "revoked": revoked or [],
    }
    env = sign_payload(manifest, SECRET, "test")
    out = tmp_path / f"update-{version}.zip"
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("update.json", json.dumps(env))
        for k, v in payload.items():
            z.writestr(k, b"evil" if tamper else v)
    return out


@pytest.mark.acceptance("ACC-060", "ACC-089", "ACC-149")
def test_offline_update_verify_apply_and_rollback(tmp_path, trust):
    root = tmp_path / "install"
    rec = updates.apply_offline_bundle(_bundle(tmp_path, "0.2.0"), root, current="0.1.0")
    assert rec.state == "COMMITTED" and updates.current_version(root) == "0.2.0"
    assert rec.history[:5] == ["AVAILABLE", "DOWNLOADING", "DOWNLOADED", "VERIFYING", "VERIFIED"]
    bad = updates.apply_offline_bundle(_bundle(tmp_path, "0.3.0"), root, current="0.2.0", validate=lambda p: False)
    assert bad.state == "ROLLED_BACK" and updates.current_version(root) == "0.2.0"
    assert not (root / "versions" / "0.3.0").exists()
    tampered = updates.apply_offline_bundle(_bundle(tmp_path, "0.4.0", tamper=True), root, current="0.2.0")
    assert tampered.state == "FAILED" and "tampered" in tampered.error
    assert "APPLYING" not in tampered.history  # never activated before verification
    assert updates.current_version(root) == "0.2.0"
    assert updates.apply_offline_bundle(_bundle(tmp_path, "0.3.1"), root, current="0.2.0").state == "COMMITTED"
    assert updates.rollback(root) == "0.2.0" and updates.current_version(root) == "0.2.0"  # ACET-UPD-004


@pytest.mark.acceptance("ACC-090", "ACC-091")
def test_revocation_blocks_new_use_but_keeps_history(tmp_path, trust, ws):
    p1 = build_pack(_config(tmp_path, "1.0.0"), tmp_path / "pack1", SECRET, "test")
    engine_packs.install_pack(p1)
    with ws.db.transaction() as tx:
        tx.execute(
            "INSERT INTO engine_pack(id, name, version, manifest_json, manifest_hash) VALUES ('ep','test-pack',"
            "'1.0.0','{}','h')"
        )
    revoke = [{"kind": "engine_pack", "id": "test-pack", "version": "1.0.0", "reason": "compromised"}]
    assert (
        updates.apply_offline_bundle(_bundle(tmp_path, "0.5.0", revoked=revoke), tmp_path / "i", current="0.1.0").state
        == "COMMITTED"
    )
    with pytest.raises(AcetError):
        engine_packs.resolve_pinned("test-pack@1.0.0")
    with pytest.raises(AcetError):
        engine_packs.verify_pack(p1)
    assert ws.db.conn.execute("SELECT count(*) FROM engine_pack WHERE name='test-pack'").fetchone()[0] == 1


def test_untrusted_signature_rejected(tmp_path, trust):
    other = bytes(32)
    env = sign_payload({"a": 1}, other, "test")
    from acet.platform.signing import load_trust_store

    with pytest.raises(AcetError):
        verify_envelope(env, load_trust_store(), purpose="update")


@pytest.mark.acceptance("ACC-092")
def test_compatibility_matrix_marks_unverified():
    assert engine_packs.provider_status("ghidra", "11.4.2") == "validated"
    assert engine_packs.provider_status("ghidra", "10.1") == "unverified"
    assert engine_packs.provider_status("qbindiff", "1.2.3") == "experimental"
    assert engine_packs.provider_status("diaphora", "3.0") == "unverified"


@pytest.mark.acceptance("ACC-059", "ACC-139", "ACC-099")
def test_sbom_and_release_evidence_gate(tmp_path, trust):
    sbom = build_sbom()
    assert sbom["bomFormat"] == "CycloneDX" and sbom["metadata"]["component"]["name"] == "acet"
    (tmp_path / "sbom.json").write_text(json.dumps(sbom))
    art = tmp_path / "ACET-Setup.exe"
    art.write_bytes(b"installer")
    out = tmp_path / "evidence"
    release_evidence.build(out, [art], tmp_path / "sbom.json", secret=SECRET, key_id="test")
    m = json.loads((out / "release-manifest.json").read_text())
    assert m["commit"] and m["artifacts"]["ACET-Setup.exe"] and m["sbom_sha256"]
    sig = json.loads((out / "signatures" / "release-manifest.sig.json").read_text())
    from acet.platform.signing import load_trust_store

    assert verify_envelope(sig, load_trust_store(), purpose="release") == m
    problems = release_evidence.check(out, "STABLE")
    # Clean-VM results are never fabricated: without them STABLE is refused.
    assert "missing: clean-vm-install-results/windows10.json" in problems
    assert release_evidence.check(out, "BETA") == []
    (out / "acceptance-matrix.json").write_text("{}")
    assert any("checksum" in p for p in release_evidence.check(out, "BETA"))
