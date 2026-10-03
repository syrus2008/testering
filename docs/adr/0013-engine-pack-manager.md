# ADR-0013 — Engine Pack Manager

- Status: Accepted
- Spec: §18, §46, §64, ACET-SUP-001..005, ACET-UPD-001; criteria ACC-ENGINE-001..006
- Builds on: ADR-0007 (provider model), ADR-0009 (Diaphora external), ADR-0011 (trust store policy)

## Context
STANDARD/DEEP need Ghidra, a Java 21 runtime and Ghidriff (an interpreter with pyghidra). The first real test on
Windows showed that "detecting" these is not enough: a user without Java/Ghidra had no way to obtain them from
ACET, and a JDK on PATH or saved in `~/.ghidra` preferences could silently be used instead of the one we audited.

## Decision
**Detect automatically, install explicitly.** `acet.platform.engine_manager` owns the whole lifecycle; the CLI
(`acet engines …`), the top-bar `Engines` button, the Engine Manager dialog and *Settings → Analysis Engines* are
thin front ends over it, run through the existing `TaskRunner` (no new job system, nothing heavy on the Qt thread).

Pipeline: resolve (signed index) → consent (version, download and installed size, components, licences) → disk
check (download + staging + installed) → download to `engines/downloads/*.part` (HTTP Range resume, then full
re-hash: correctness over clever resume) → archive SHA-256 → manifest signature, schema, compatibility, licences,
revocation → safe extraction into `engines/staging/<uuid>` (member-name policy, no traversal / absolute / reserved
names / duplicates / links, size and ratio limits, every file hashed while written) → `os.replace` into
`engines/packs/<id>-<ver>` with an `.acet-installing` marker → private-Java pinning → real `doctor --full` golden
self-test on that pack → re-verification that running the engines did not modify the pack → verification record →
atomic switch of `engines/current.json` (`active`, `previous`). Any failure or cancel leaves the previous pack
active; `recover()` (run at every start, in the background) removes staging and marked packs and repairs a
dangling pointer. Errors are explicit (`ACET-EPM-001..012`: NETWORK_UNAVAILABLE, TLS_ERROR, PROXY_REQUIRED,
DOWNLOAD_INTERRUPTED, SIGNATURE_INVALID, HASH_MISMATCH, PACK_INCOMPATIBLE, DISK_SPACE_INSUFFICIENT,
INTEGRITY_FAILURE, HEALTH_CHECK_FAILED, NO_DISTRIBUTION, REVOKED). `engine-pack-install.log` never records URL
credentials or query strings.

**Trust.** The index must be signed by a key of the bundled store (`load_trust_store(local=False)`); HTTPS alone
is not integrity. Pack manifests follow ADR-0011 (local admin keys may add `engine-pack` keys only). No URL is
hard-coded: `src/acet/platform/distribution.json` lists the official HTTPS index URLs (empty until the release
owner publishes one); `ACET_ENGINE_INDEX_URL` can point to a mirror, still signature-checked. "Install from file…"
runs exactly the same validations as a download.

**Private Java.** A pack declares `runtime.java.path`. Detection then never falls back to a system Java; workers
get `JAVA_HOME`/`PATH` for their own process tree only; and the manager writes
`JAVA_HOME_OVERRIDE=<pack runtime>` into Ghidra's `support/launch.properties`, which Ghidra's launcher honours
before `~/.ghidra` preferences, `JAVA_HOME` or `PATH`. Verification accepts that single line, and only when it points
to the pack's own runtime. Nothing is installed system-wide. Engine interpreters write their bytecode cache to
`<ACET_HOME>/cache/pycache` (`PYTHONPYCACHEPREFIX`), so the pack stays byte-identical to its signed manifest.

**Readiness.** A profile is READY only when every non-optional processor's providers are detected **and** the
pack's health check verified them; optional ones make it DEGRADED; a folder on disk, a replay provider or an
unverified pack is never READY. Components are REQUIRED (Java, Ghidra, Ghidriff), OPTIONAL (BinExport, BinDiff,
QBinDiff) or EXTERNAL (Diaphora: AGPL and needs IDA, never redistributed — ADR-0009), each with a "why".

**Repair / update / rollback.** Verify re-hashes every file; Repair restores only the damaged files from a
verified archive of the same pack, otherwise asks for one. Updates are user-initiated (`CURRENT`,
`UPDATE_AVAILABLE`, `UNSUPPORTED`, `REVOKED`); Rollback reactivates `previous`.

## Consequences
- Remote installation is unavailable (NO_DISTRIBUTION, with "Install from file…" offered) until the release owner
  adds a release key to the bundled store, publishes a signed index and lists its URL in `distribution.json`.
- The Windows pack must ship Ghidriff on an embeddable CPython (`ghidriff/python.exe`, `python311._pth` including
  `Lib/site-packages`) — a Linux venv is not relocatable and is only used for the Linux evidence run.
- "Standalone" is claimed only after MP-006 (ACC-ENGINE-001) passes on a clean Windows VM.
