# Engine Pack Manager — live end-to-end run (Linux x64, 2026-10-03)

Purpose: exercise the real pipeline with real engines before the Windows protocol MP-006 (ACC-ENGINE-001).
This is **not** the clean-Windows validation: the machine had a system Python (ACET runs from source) and a
system JDK, which were deliberately made unusable (`JAVA_HOME=/nonexistent/jdk`, JVM directories removed from
`PATH`) to show the pack's private Java is the one used.

Pack built with `tools/build_engine_pack.py` from Ghidra 11.4.2, an OpenJDK 21.0.11 runtime (copied into
`runtime/java`) and a Ghidriff 1.0.0 + pyghidra interpreter; signed with a throw-away test key that played the
release key for the index only (test key, never committed). Archive 542,682,522 bytes; installed 1,024,161,063 bytes.

| Step | Result |
|---|---|
| `acet engines status` before | `DEGRADED`, FAST READY, STANDARD/DEEP UNAVAILABLE, exit 10 |
| `acet engines install --file … --yes` (offline path) | READY in 93 s, health check VERIFIED (live) |
| `acet engines verify` right after | **REPAIR_REQUIRED** — the embedded interpreter had written `__pycache__/*.pyc` into the pack during the health check. Fixed: `PYTHONPYCACHEPREFIX` outside the pack + integrity re-check after the health check. |
| signed index over HTTP → consent → download → install (fresh home) | consent showed id, version, sizes, components + licences; READY in 96 s; steps VERIFYING, EXTRACTING, VALIDATING, HEALTH_CHECK, ACTIVATED |
| `launch.properties` | `JAVA_HOME_OVERRIDE=<home>/engines/packs/acet-engines-linux64-1.0.0/runtime/java` |
| `acet engines status` after | `READY`; Java 21.0.11 READY, Ghidra 11.4.2 READY, Ghidriff 1.0.0 READY; FAST/STANDARD READY, DEEP/RESEARCH DEGRADED (BinDiff/QBinDiff optional, not in pack) |
| `acet engines verify` (after install and after `doctor --full`) | VERIFIED, 0 bad files |
| `acet doctor --full` | engine pack READY; `java: 21.0.11 (engine-pack)`; ghidra/ghidriff validated; golden self-test **VERIFIED (engines: live)** incl. STANDARD golden consensus and live Ghidra extraction; overall DEGRADED (Linux platform warning, optional providers) |
| install pack 1.1.0 with a broken Java | `ACET-EPM-010 HEALTH_CHECK_FAILED`, exit 30; 1.0.0 still active and VERIFIED; staging empty; no 1.1.0 directory left |
| `tests/integration/test_live_engines.py` on the pack's engines (`ACET_GHIDRA_DIR`, `ACET_GHIDRIFF_PYTHON`, `JAVA_HOME` = pack paths) | live STANDARD compare matches the golden extraction (ACC-038) and live Ghidriff passes: 2 passed in 136 s; BinDiff/QBinDiff test skipped (not in pack); `acet engines verify` still VERIFIED afterwards |
