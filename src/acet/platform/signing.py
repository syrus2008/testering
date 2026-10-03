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

# Trust policy (ADR-0011). The bundled store ships with the reviewed source tree and is the
# only source for keys that can sign application updates or releases. Local sources (the
# per-user admin file and an explicit --trust file) are writable by whoever controls the
# machine, so they may only:
#   * add keys for LOCAL_PURPOSES (an organisation signing its own Engine Packs), and
#   * revoke keys (revocation is sticky: once revoked in any source, a key stays revoked).
# They can never redefine a bundled key, un-revoke a key, or grant "update"/"release".
LOCAL_PURPOSES = frozenset({"engine-pack"})
KNOWN_PURPOSES = frozenset({"engine-pack", "update", "release"})


def _bundled_store() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (resources.files("acet.platform") / "trusted_keys.json").read_text(encoding="utf-8")
    )
    return data


def _valid_key(k: Any) -> bool:
    if not isinstance(k, dict) or not isinstance(k.get("key_id"), str) or not k["key_id"]:
        return False
    pub = k.get("public_key")
    purposes = k.get("purposes")
    return (
        k.get("alg") == "ed25519"
        and isinstance(pub, str)
        and len(pub) == 64
        and all(c in "0123456789abcdef" for c in pub)
        and isinstance(purposes, list)
        and set(purposes) <= KNOWN_PURPOSES
    )


def load_trust_store(extra: Path | None = None, *, local: bool = True) -> dict[str, dict[str, Any]]:
    """Merge the trust sources under the policy above. Malformed entries or a conflicting
    redefinition of a key fail closed (ACET-PACK-001). ``local=False`` uses the bundled store only."""
    keys: dict[str, dict[str, Any]] = {}
    revoked: set[str] = set()
    for k in _bundled_store().get("keys", []):
        if not _valid_key(k):
            raise AcetError(
                "ACET-PACK-001", f"malformed bundled trusted key {k.get('key_id') if isinstance(k, dict) else k!r}"
            )
        keys[k["key_id"]] = {**k, "source": "bundled"}
        if k.get("revoked"):
            revoked.add(k["key_id"])
    bundled_ids = set(keys)
    sources: list[Path] = []
    if local:
        sources = [p for p in (acet_home() / "config" / "trusted_keys.json", extra) if p is not None and p.is_file()]
    for path in sources:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AcetError("ACET-PACK-001", f"unreadable trust store {path}") from exc
        for k in data.get("keys", []) if isinstance(data, dict) else []:
            kid = k.get("key_id") if isinstance(k, dict) else None
            if isinstance(kid, str) and k.get("revoked") is True and set(k) <= {"key_id", "revoked", "reason"}:
                revoked.add(kid)  # revocation-only entry
                continue
            if not _valid_key(k) or not isinstance(kid, str):
                raise AcetError("ACET-PACK-001", f"malformed trusted key {kid!r} in {path}")
            if k.get("revoked"):
                revoked.add(kid)
            prev = keys.get(kid)
            if prev is not None:
                if prev["public_key"] != k["public_key"]:
                    raise AcetError("ACET-PACK-001", f"trust store conflict: {kid} redefined in {path}")
                if kid in bundled_ids:
                    continue  # a local source never widens a bundled key
            granted = sorted(set(k["purposes"]) & LOCAL_PURPOSES)
            if prev is not None:
                granted = sorted(set(granted) | set(prev["purposes"]))
            keys[kid] = {**k, "purposes": granted, "source": str(path)}
    for kid in revoked & set(keys):
        keys[kid] = {**keys[kid], "revoked": True}
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
