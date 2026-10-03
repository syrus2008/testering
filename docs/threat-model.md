# ACET threat model (v0.1, spec §48, §61, §79)

Assets: the user's artifacts (possibly sensitive), workspace integrity, provenance, and the user's machine.

| Threat | Mitigation | Status |
|---|---|---|
| Hostile binary | Never executed (ADR-0010); header parsing bounded to 64 KiB; workers isolated | Import: done. Workers: P3 |
| Parser crash | Malformed headers return `None`; engine parsers run out of process | done / P3 |
| Path traversal | Canonical resolve; `.acetpack` paths validated by schema pattern; store paths derived from SHA only | store: done. pack: P11 |
| Reparse/symlink loops | (dev, inode) visited set + max depth (ACC-065) | done |
| Zip / archive bomb | Entry count, total size, ratio and depth limits before extraction (ACET-ARC-001) | P11 |
| Disk exhaustion | Preflight before copy (ACET-IMP-003); atomic temp + rename | done |
| DB corruption | WAL, FK, integrity_check, backup API, atomic migrations, RECOVERY_READ_ONLY | done |
| Tampered bytes in store | Re-hash before analysis; CORRUPTED state blocks analysis (ACC-008) | done |
| Exfiltration | No network code in Core; telemetry off; symbols fetch opt-in | done (by absence) |
| Log / diagnostic leakage | Full source paths never stored (labels = base names); PDB paths treated as sensitive | partial |
| Tampered Engine Pack / update | Signed manifests, hashes, denylist (ACET-SUP-001..005) | P12 |
| Privilege | No admin required; workers with minimal env | done / P3 |
