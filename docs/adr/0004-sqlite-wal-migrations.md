# ADR-0004 — SQLite WAL + atomic migrations

- Status: Accepted
- Spec: §9, §10, §63, ACET-DB-001..006, ACET-TXN-001, ACET-DR-001, §115

## Decision
- Every connection runs `PRAGMA foreign_keys=ON` and verifies it. It also sets `busy_timeout=5000` and
  `synchronous=FULL`.
- WAL is requested and the actual mode is recorded. A fallback is logged and surfaced by Doctor.
- Transactions are explicit (`BEGIN IMMEDIATE`) and short. Hashing, copying and engine work never run inside one.
  Durations are recorded (instrumentation for ACC-107).
- The schema version is `PRAGMA user_version`, mirrored in `workspace.schema_version`.
- Migration sequence: Online-Backup-API snapshot → a single transaction applying every pending migration → `integrity_check` +
  `foreign_key_check` → COMMIT. On failure: ROLLBACK, and if the DB is not provably at its previous version and intact,
  restore the pre-migration backup.
- Hot backup always uses the SQLite backup API, never a file copy of `acet.db` alone.
- Restore sequence: temp copy → integrity_check → atomic swap. An invalid backup never touches the active DB.
- On startup a `quick_check` failure opens the workspace `RECOVERY_READ_ONLY`.
- A DB schema newer than the app is refused read-write (read-only open allowed).
- Audit events are append-only, enforced by triggers.
