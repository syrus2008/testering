"""Trust store policy (ADR-0011): local sources can add Engine Pack keys and revoke, nothing more."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acet.domain.error_codes import AcetError
from acet.platform import ed25519, signing
from acet.platform.signing import load_trust_store, sign_payload, verify_envelope

BUNDLED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
LOCAL = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")


def _key(kid: str, secret: bytes, purposes: list[str], **extra: object) -> dict[str, object]:
    return {
        "key_id": kid,
        "alg": "ed25519",
        "public_key": ed25519.public_key(secret).hex(),
        "purposes": purposes,
        **extra,
    }


@pytest.fixture
def admin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(signing, "_bundled_store", lambda: {"keys": [_key("vendor", BUNDLED, ["update", "release"])]})
    path = tmp_path / "acet-home" / "config" / "trusted_keys.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    def write(*keys: dict[str, object]) -> Path:
        path.write_text(json.dumps({"keys": list(keys)}))
        return path

    return write


def test_local_file_cannot_grant_update_or_release(admin):
    admin(_key("mine", LOCAL, ["update", "release", "engine-pack"]))
    store = load_trust_store()
    assert store["mine"]["purposes"] == ["engine-pack"]
    for purpose in ("update", "release"):
        with pytest.raises(AcetError):
            verify_envelope(sign_payload({"x": 1}, LOCAL, "mine"), store, purpose=purpose)
    assert verify_envelope(sign_payload({"x": 1}, LOCAL, "mine"), store, purpose="engine-pack") == {"x": 1}


def test_local_file_cannot_redefine_or_widen_a_bundled_key(admin):
    admin(_key("vendor", LOCAL, ["update"]))
    with pytest.raises(AcetError, match="conflict"):
        load_trust_store()
    admin(_key("vendor", BUNDLED, ["update", "release", "engine-pack"]))
    assert load_trust_store()["vendor"]["purposes"] == ["update", "release"]


def test_revocation_is_sticky(admin, monkeypatch):
    admin({"key_id": "vendor", "revoked": True, "reason": "compromised"})
    with pytest.raises(AcetError):
        verify_envelope(sign_payload({"x": 1}, BUNDLED, "vendor"), load_trust_store(), purpose="update")
    # A key revoked in the bundled store cannot be revived locally.
    monkeypatch.setattr(
        signing, "_bundled_store", lambda: {"keys": [_key("vendor", BUNDLED, ["update"], revoked=True)]}
    )
    admin(_key("vendor", BUNDLED, ["update"], revoked=False))
    assert load_trust_store()["vendor"]["revoked"] is True


def test_malformed_entries_fail_closed(admin):
    admin({"key_id": "bad", "alg": "rsa", "public_key": "00", "purposes": ["engine-pack"]})
    with pytest.raises(AcetError, match="malformed"):
        load_trust_store()
    admin(_key("odd", LOCAL, ["root-of-everything"]))
    with pytest.raises(AcetError, match="malformed"):
        load_trust_store()


def test_bundled_only_mode_ignores_local_sources(admin, tmp_path):
    admin(_key("mine", LOCAL, ["engine-pack"]))
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"keys": [_key("other", LOCAL, ["engine-pack"])]}))
    assert set(load_trust_store(extra)) == {"vendor", "mine", "other"}
    assert set(load_trust_store(extra, local=False)) == {"vendor"}


def test_release_gate_ignores_locally_added_release_keys(admin, tmp_path):
    import sys

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    from tools import release_evidence

    admin(_key("mine", LOCAL, ["release"]))
    out = tmp_path / "ev"
    art = tmp_path / "setup.exe"
    art.write_bytes(b"x")
    release_evidence.build(out, [art], None, secret=LOCAL, key_id="mine")
    assert any("signature invalid" in p for p in release_evidence.check(out, "BETA"))
