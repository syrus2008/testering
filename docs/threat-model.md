# ACET threat model (v0.1, spec §48, §61, §79)

Assets: the user's artifacts (possibly sensitive), workspace integrity, provenance, and the user's machine.

| Threat | Mitigation | Status |
|---|---|---|
| Hostile binary | Never executed (ADR-0010); bounded static parsing; isolated workers; blobs without exec bit | done (runtime test ACC-004) |
| Parser crash | PE parser fuzzed; every processor runs in a supervised worker | done |
| Path traversal | Canonical resolve; archive path checks; store paths derived from SHA only | done |
| Reparse/symlink loops | (dev, inode) visited set + max depth (ACC-065) | done |
| Zip / archive bomb | Entry count, size, ratio, depth limits; encrypted entries refused (no password guessing) | done |
| Disk exhaustion | Preflight before copy (ACET-IMP-003); atomic temp + rename | done |
| DB corruption | WAL, FK, integrity_check, backup API, atomic migrations, RECOVERY_READ_ONLY | done |
| Tampered bytes in store | Re-hash before analysis; CORRUPTED state blocks analysis (ACC-008) | done |
| Exfiltration | No network code in Core; analysis workers block sockets; telemetry off; no symbol fetch | done (ACC-003/078) |
| Log / diagnostic leakage | Base names only; sanitized diagnostics (paths, user, PDB) | done (ACC-032/076) |
| Tampered Engine Pack / update | Ed25519-signed manifests, per-file hashes, denylist, staged apply + rollback | done (ACC-058/149) |
| Privilege | asInvoker manifest; runs as an unprivileged user; workers with minimal env | done (ACC-079) |

Open items: AppContainer / low-integrity workers are not enabled (ACET-SEC-005 gate: requires per-provider golden compatibility tests first). Engine subprocesses (java, ghidriff) are not socket-blocked by ACET itself; deploy a Windows Firewall rule for the Engine Pack directory.
