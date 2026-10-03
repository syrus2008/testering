# Engine Pack — live acceptance on Windows (REAL-TEST-002, 2026-10-03)

Run: `engine-pack` workflow, run 37152983744, job `live` (commit 4723c01) —
https://github.com/syrus2008/testering/actions/runs/37152983744

Machine: GitHub-hosted Windows Server 2025 (image windows-2025-vs2026) with the environment of REAL-TEST-002:
every Java/JDK/JRE/Ghidra entry removed from `PATH`, `JAVA_HOME*` cleared, no Ghidriff/pyghidra in the
interpreter running ACET (asserted by the test before anything else). ACET runs from source on Python 3.11.9
(the installer's embedded Python is a separate step: see "Limits").

Tests: `tests/live/test_engine_pack_live.py` — **2 passed in 778.71 s**.

## 1. Install Engine Pack from the Engines button (UI, offscreen Qt)
Engines button → Engine Manager → **Install Engine Pack** → consent dialog (entry below) → accept.

Consent shown before any download (signed index entry):
- `acet-engines-win64` 1.0.0, platform `win-x64`, download 549,020,988 bytes, installed 1,034,298,708 bytes
- Eclipse Temurin JDK 21.0.8+9 (private runtime) — GPL-2.0-only WITH Classpath-exception-2.0
- Ghidra 11.4.2 — Apache-2.0 (+ third-party licenses in ghidra/licenses)
- Ghidriff 1.0.0 on a private CPython 3.11.9 (pyghidra 2.2.1, JPype 1.5.2, mdutils 1.6.0) — GPL-3.0-only,
  Apache-2.0, MIT, PSF-2.0

`engine-pack-install.log`:
```
2026-10-03T20:52:10.285378Z RESOLVED index=https://github.com/syrus2008/testering/releases/download/engine-pack-index-dev/index.json pack=acet-engines-win64@1.0.0
2026-10-03T20:52:10.288378Z DOWNLOAD_START size=549020988 url=https://github.com/syrus2008/testering/releases/download/engine-pack-win64-1.0.0/acet-engines-win64-1.0.0.acetengine
2026-10-03T20:52:19.287722Z DOWNLOAD_VERIFIED sha256=a5005190ad8ef10d73bf291aab26dedab8753114191ba1ac0320dc5873ff102b size=549020988
2026-10-03T20:52:20.031972Z INSTALL_START archive_sha256=a5005190ad8ef10d73bf291aab26dedab8753114191ba1ac0320dc5873ff102b pack=acet-engines-win64@1.0.0 source=https://github.com/syrus2008/testering/releases/download/engine-pack-index-dev/index.json
2026-10-03T20:54:24.574695Z HEALTH_CHECK engines=live pack=acet-engines-win64-1.0.0 verdict=VERIFIED
2026-10-03T20:54:30.240851Z ACTIVATED pack=acet-engines-win64-1.0.0

```
(download 9 s, verification + extraction + live health check 2 min 10 s.)

## 2. `doctor --full` after the UI installation
```
ACET 0.1.0 — DEGRADED
  [OK           ] python: 3.11.9
  [OK           ] platform: Windows 10
  [OK           ] sqlite: 3.45.1
  [OK           ] acet: 0.1.0
  [OK           ] engine pack: acet-engines-win64@1.0.0 READY
  [OK           ] profiles: FAST READY, STANDARD READY, DEEP DEGRADED, RESEARCH DEGRADED
  [OK           ] java: 21.0.8 (engine-pack)
  [OK           ] ghidra: 11.4.2 — validated
  [OK           ] ghidriff: 1.0.0 — validated
  [NOT_AVAILABLE] binexport: BinExport Ghidra extension not installed
  [NOT_AVAILABLE] bindiff: bindiff executable not found
  [NOT_AVAILABLE] qbindiff: isolated QBinDiff interpreter not configured
  [NOT_AVAILABLE] diaphora: external IDA-based provider: detection only (ADR-0009)
  [OK           ] golden self-test: VERIFIED (engines: live); import=True; FAST facts=True; STANDARD golden consensus=True; golden Ghidra extraction=True

```
Overall `DEGRADED` only because the optional providers (BinExport/BinDiff/QBinDiff) and the external Diaphora are
not in this pack; STANDARD is `READY`. ("platform: Windows 10" is how Python reports Windows Server 2025.)

## 3. Real STANDARD analysis on the pack's engines
Demo builds v1 → v2, `STANDARD@1`: status **COMPLETED**, coverage 1.0, no missing evidence; 4 live
`ghidra.extract` (identical to the recorded golden extraction), 2 `ghidriff.diff`, feature match and consensus all
SUCCESS. Run recorded against engine pack `acet-engines-win64@1.0.0`; matchers `acet.featurematch 2`,
`ghidriff ghidriff-1.0.0`.

## 4. Install from file… — the same archive, fresh ACET home
Steps VERIFYING → EXTRACTING → VALIDATING → HEALTH_CHECK → ACTIVATED, verdict VERIFIED, then:
```
ACET 0.1.0 — DEGRADED
  [OK           ] python: 3.11.9
  [OK           ] platform: Windows 10
  [OK           ] sqlite: 3.45.1
  [OK           ] acet: 0.1.0
  [OK           ] engine pack: acet-engines-win64@1.0.0 READY
  [OK           ] profiles: FAST READY, STANDARD READY, DEEP DEGRADED, RESEARCH DEGRADED
  [OK           ] java: 21.0.8 (engine-pack)
  [OK           ] ghidra: 11.4.2 — validated
  [OK           ] ghidriff: 1.0.0 — validated
  [NOT_AVAILABLE] binexport: BinExport Ghidra extension not installed
  [NOT_AVAILABLE] bindiff: bindiff executable not found
  [NOT_AVAILABLE] qbindiff: isolated QBinDiff interpreter not configured
  [NOT_AVAILABLE] diaphora: external IDA-based provider: detection only (ADR-0009)
  [OK           ] golden self-test: VERIFIED (engines: live); import=True; FAST facts=True; STANDARD golden consensus=True; golden Ghidra extraction=True
```

## 5. `acet engines status` (workflow step, fresh process)
```
Engine Pack: acet-engines-win64@1.0.0
State: READY
  FAST      READY
  STANDARD  READY
  DEEP      DEGRADED
  RESEARCH  DEGRADED
  Java Runtime   REQUIRED  READY           21.0.8
  Ghidra         REQUIRED  READY           11.4.2
  Ghidriff       REQUIRED  READY           1.0.0
  BinExport      OPTIONAL  NOT_INSTALLED   
  BinDiff        OPTIONAL  NOT_INSTALLED   
  QBinDiff       OPTIONAL  NOT_INSTALLED   
  Diaphora       EXTERNAL  NOT_CONFIGURED  
```

## The artifact
- Release: https://github.com/syrus2008/testering/releases/tag/engine-pack-win64-1.0.0
- `acet-engines-win64-1.0.0.acetengine` — SHA-256 `a5005190ad8ef10d73bf291aab26dedab8753114191ba1ac0320dc5873ff102b`, 549,020,988 bytes
- signed manifest `packaging/engine-pack/win64/engine-pack.json` (key `acet-dev-engines-2026-10`), build record
  `packaging/engine-pack/win64/build-info.json`, signed index `packaging/engine-pack/dev-index.json`
  (published at https://github.com/syrus2008/testering/releases/download/engine-pack-index-dev/index.json)

## Failures found and fixed on the way (real runs, not hypotheses)
1. First live run: `HEALTH_CHECK_FAILED`, no cause given → health failures now carry the failing checks and the
   engines' log tails (`logs/engine-pack-health-*.json`).
2. Second run, cause: ACET's Ghidra script bundle imported the optional BinExport extension → nothing loaded without
   it. BinExport script moved to its own directory; stale compiled bundles purged (commit 4723c01).

## Limits (not claimed by this run)
- ACET itself ran from source on the runner's Python 3.11.9, not from `ACET-Setup.exe`: the frozen installer path
  (embedded Python) is covered by the `packaging` job of `ci.yml`, but the combination *installer + Install Engine
  Pack* on a clean Windows 10/11 VM is protocol MP-006 (ACC-ENGINE-001), still to be executed by a person.
- Hosted runner, not a desktop: Qt ran offscreen; the Engines button and Install button were clicked programmatically.
- The pack is signed with the **dev** channel key; a STABLE release refuses it (official key and channel needed).
- BinExport/BinDiff/QBinDiff are not in the pack (optional, DEEP); Diaphora stays external (AGPL + IDA).
