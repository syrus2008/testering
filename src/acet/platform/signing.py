"""Signed manifests and trust store (spec §64, ACET-SUP-001..005, ACC-057/058/099).

Envelope: {"payload": {...}, "signatures": [{"alg": "ed25519", "key_id": "...", "sig": "<hex>"}]}
The signature covers ``canonical_json(payload)``. Trusted public keys come from the
trust store (``trusted_keys.json`` bundled with the app + an optional admin file);
private keys never live in the repository.
"""

from __future__ import annotations

import contextlib
import json
from importlib import resources
from pathlib import Path
from typing import Any

from acet.domain.canonical import canonical_json, stable_json
from acet.domain.error_codes import AcetError
from acet.platform import ed25519
from acet.platform.paths import acet_home


def load_trust_store(extra: Path | None = None) -> dict[str, dict[str, Any]]:
    keys: dict[str, dict[str, Any]] = {}
    bundled = json.loads((resources.files("acet.platform") / "trusted_keys.json").read_text(encoding="utf-8"))
    sources = [bundled]
    admin = acet_home() / "config" / "trusted_keys.json"
    for p in (admin, extra):
        if p is not None and p.is_file():
            sources.append(json.loads(p.read_text(encoding="utf-8")))
    for src in sources:
        for k in src.get("keys", []):
            keys[k["key_id"]] = k
    return keys


def _payload_bytes(payload: Any) -> bytes:
    try:
        return canonical_json(payload)
    except TypeError:
        return stable_json(payload)


def sign_payload(payload: dict[str, Any], secret: bytes, key_id: str) -> dict[str, Any]:
    sig = ed25519.sign(secret, _payload_bytes(payload))
    return {"payload": payload, "signatures": [{"alg": "ed25519", "key_id": key_id, "sig": sig.hex()}]}


def verify_envelope(envelope: dict[str, Any], trust: dict[str, dict[str, Any]], *, purpose: str) -> dict[str, Any]:
    """Return the payload if at least one signature verifies with a trusted, non-revoked key for ``purpose``."""
    if not isinstance(envelope, dict) or "payload" not in envelope:
        raise AcetError("ACET-PACK-001", "not a signed envelope")
    msg = _payload_bytes(envelope["payload"])
    for s in envelope.get("signatures", []):
        k = trust.get(s.get("key_id", ""))
        if not k or s.get("alg") != "ed25519" or k.get("revoked") or purpose not in k.get("purposes", []):
            continue
        try:
            if ed25519.verify(bytes.fromhex(k["public_key"]), msg, bytes.fromhex(s["sig"])):
                payload: dict[str, Any] = envelope["payload"]
                return payload
        except ValueError:
            continue
    raise AcetError("ACET-PACK-001", f"no valid trusted signature for {purpose} (ACET-SUP-001)")


def keygen(dest_secret: Path, key_id: str, purposes: list[str]) -> dict[str, Any]:
    """Create a release key. The secret file must be stored outside the repository (§75 Signing)."""
    secret = ed25519.generate_secret()
    dest_secret.parent.mkdir(parents=True, exist_ok=True)
    dest_secret.write_text(secret.hex(), encoding="ascii")
    with contextlib.suppress(OSError):
        dest_secret.chmod(0o600)
    return {"key_id": key_id, "alg": "ed25519", "public_key": ed25519.public_key(secret).hex(), "purposes": purposes}
