# ACET recovery runbook (spec §58 Support, §114)

Recovery priority: **preserve the active workspace → stop writers → snapshot diagnostics → validate the latest backup →
rebuild indexes/caches from canonical data → restore DB only if required → reconcile the store → recompute derived
results.** Never "repair" by deleting unknown data.

| Symptom (code) | What it means | Do this |
|---|---|---|
| Health **ACTION REQUIRED**, `database.integrity` FAIL (ACET-DB-001) | SQLite image damaged; workspace opened `RECOVERY_READ_ONLY` | `acet diagnostics diag.zip`; `acet restore <workspace>/backups/<latest>.db` (validated before swap); then `acet reconcile --deep` |
| Migration failed (ACET-DB-002) | Rolled back automatically from the pre-migration backup | Keep using the previous ACET version; send the diagnostic package |
| Schema newer than app (ACET-DB-003) | Workspace written by a newer ACET | Open read-only or install the newer version |
| Artifact corrupted / missing (ACET-STO-002 / 001) | Blob failed re-hash or is absent; analysis blocked | Re-import the original file (identical bytes repair it) or restore; `acet reconcile` |
| Orphan blobs reported by reconcile | Bytes copied before a crash, never committed | `acet reconcile --quarantine-orphans` (moves, never deletes); `acet cleanup` after the retention |
| Interrupted job (ACET-JOB-002) | App/worker stopped during analysis | `acet jobs list` (recovers), then `acet jobs resume <id>`; finished nodes are not redone |
| Heartbeat lost / HUNG (ACET-JOB-001) | Engine stopped making progress | Retry; raise the profile timeout if the binary is large; check Doctor known limitations |
| Ghidra unavailable (ACET-GHD-001) | No Engine Pack / Java | Install or pin the official Engine Pack; FAST remains available (DEGRADED) |
| `Engines: ✖ REPAIR REQUIRED` / ACET-EPM-009 | Files of the active pack modified or missing | `acet engines verify` lists them; `acet engines repair --file <same .acetengine>` restores only those files |
| ACET-EPM-001/002/003 (network, TLS, proxy) | No route to the distribution | Use *Install from file…* with an `.acetengine` obtained elsewhere (same validations) |
| ACET-EPM-010 health check failed | The new pack's engines do not pass `doctor --full` | Nothing changed: the previous pack stays active; send `logs/engine-pack-install.log` |
| ACET stopped during an Engine Pack install | Crash / power loss | Automatic at next start (`acet engines recover`): staging and half-installed packs removed, previous pack kept |
| ACET-EPM-011 NO_DISTRIBUTION | No signed index configured yet | Release owner: add the release key to `trusted_keys.json`, publish the index signed by it (`tools/build_engine_pack.py --index`), list its HTTPS URL in `distribution.json` |
| Ghidra timeout (ACET-GHD-002) | Native or watchdog timeout; extraction partial | Run with a longer timeout profile; partial facts are kept |
| `COMPLETED_PARTIAL` | An optional engine was missing/failed | Read *Missing evidence* in the run/report; install the provider and re-run (cache keeps the rest) |
| Pack refused (ACET-PACK-001 / 002, ACET-SEC-001 / 002) | Tampered, unsafe or newer pack | Obtain an intact pack / newer ACET; nothing was written |
| Engine Pack incompatible / revoked (ACET-UPD-001) | Signature, compatibility or denylist | Install a compatible, non-revoked pack; historical runs remain readable |
| Update rolled back | Post-update validation failed | Previous version restored automatically; send diagnostics |
| Disk full (ACET-IMP-003) | Preflight or write refused | Free space or move the workspace; `acet cleanup` (dry run first) |
| Database busy (ACET-DB-004) | Another ACET operation holds the write lock | Retry when it finishes |

Diagnostic package: `acet diagnostics <file.zip>` — versions, provider states, job states, integrity result,
sanitized settings and log tails. No artifact bytes, no full user paths.
