# ADR-0003 — Content-addressable artifact store

- Status: Accepted
- Spec: §8, ACET-STO-001..003, ACET-DATA-001, ACET-IMP-002/003, INV-001/002

## Decision
- Identity is the lowercase hex SHA-256. Path: `artifacts/sha256/ab/cd/<sha256>` (short, avoiding long-path problems).
- The write path is: hash source → copy into `temp/` on the same volume while hashing → fsync → re-hash the landed file →
  compare with the source hash → `chmod` read-only → `os.replace` into place. Any mismatch fails with ACET-IMP-002, and
  nothing is renamed.
- Existing bytes are never re-copied or replaced. A second import creates references and observations only.
- `*.tmp` files in `temp/` are never valid output (ACC-095). Reconcile reports them.
- Orphans (a blob with no row) are moved to `quarantine/` on explicit request only, never deleted (ACET-STO-003, §114).
- A per-hash in-process lock serializes COPY/VERIFY. Concurrent writers of the same hash produce identical bytes,
  and the atomic rename is idempotent.

## Consequences
Crash between copy and commit leaves orphan blobs, which reconcile detects (ACC-082/140). The next import
of the same file reuses them.
