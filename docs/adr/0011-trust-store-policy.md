# ADR-0011 — Trust store policy

- Status: Accepted
- Spec: ACET-SUP-001..005, ACET-UPD-001, ACET-REL-001, ACC-057/058/099

## Context
Signatures are only as strong as the list of keys that are trusted. Before this decision, any
`trusted_keys.json` in the per-user ACET home (or passed with `--trust`) was merged over the bundled
store, so a key could be added, replaced or un-revoked for any purpose, including application
updates and the STABLE release gate.

## Decision
`acet.platform.signing.load_trust_store` applies a fixed policy:

| Source | May add keys for | May revoke | May redefine / widen a bundled key |
|---|---|---|---|
| bundled `src/acet/platform/trusted_keys.json` (reviewed source tree) | `engine-pack`, `update`, `release` | yes | — |
| per-user admin file, `--trust` file (writable by whoever controls the machine) | `engine-pack` only | yes | never |

- Revocation is sticky: a key revoked in any source stays revoked; no source can revive it.
- A local entry that reuses a known `key_id` with another public key is a conflict and fails closed
  (`ACET-PACK-001`); with the same key it can only narrow (revoke), never add purposes.
- Malformed entries (algorithm, key length, unknown purpose) fail closed.
- The release gate (`tools/release_evidence.py check`) reads the bundled store only (`local=False`) and has
  no `--trust` option: a release key exists only if it was committed and reviewed.

## Consequences
An organisation can sign and install its own Engine Packs without rebuilding ACET; trusting a new update or
release key requires a reviewed change to the bundled store and a new ACET build. Tests that need a trusted
update/release key patch the bundled store (`signing._bundled_store`), mirroring that rule.
