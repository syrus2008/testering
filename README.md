# ACET — Anti-Cheat Evolution Tracker

ACET is a local, offline-first Windows application for **longitudinal comparison of binary components**. It
imports user-supplied artifacts, groups them into builds and observations, extracts reproducible facts, matches
functions across versions with several engines, builds function lineages, flags unusual changes per dimension,
and produces inspectable reports. It **never executes** an imported artifact.

The normative specification is [`docs/spec/ACET_Master_Specification_v3_FINAL.docx`](docs/spec/ACET_Master_Specification_v3_FINAL.docx)
(a text extract sits next to it). Requirement IDs (`ACET-*`, `ACC-*`, `INV-*`) in code, tests and docs refer to it.

## Status

All roadmap phases P0–P13 (spec §56) are implemented.

| Phase | Deliverable | Where |
|---|---|---|
| P0–P2 | Domain, SQLite/migrations, content-addressed store, import | `domain/`, `storage/`, `ingest/` |
| P3 | Jobs, supervised workers (process-tree kill, heartbeat, bounded logs), recovery | `jobs/` |
| P4 | FAST facts (static PE incl. Authenticode digest check), DAG, cache, STALE | `analysis/` |
| P5–P6 | Ghidra headless extraction, Ghidriff, normalized matcher DTO | `engines/` |
| P7–P8 | Evidence-family consensus, N-way lineage, BinExport/BinDiff, QBinDiff | `matching/`, `lineage/`, `engines/` |
| P9–P10 | Change dimensions + baselines + events, Benchmark Lab, calibration, gates | `changes/`, `benchmark/` |
| P11 | Reports, `.acetpack`, diagnostics, retention/purge, backup/restore, search | `reporting/`, `platform/`, `application/` |
| P12 | Signed Engine Packs, verified offline updates, SBOM, release evidence, packaging | `platform/`, `tools/`, `packaging/` |
| P13 | PySide6 UI (all pages, Ctrl+K, wizards, background tasks) | `ui/` |

**Acceptance criteria** ([matrix](docs/traceability/acceptance-matrix.json)): 145 of 150 automated; ACC-001, 025,
056, 100 and 150 need a clean Windows VM / production certificate and are covered by versioned
[manual protocols](docs/acceptance/manual-protocols.md). **Requirements** ([matrix](docs/traceability/requirement-matrix.json)):
135/135 implemented and verified or explicitly waived (2 waivers, justified).

### Verified with real engines (Linux CI container)
Ghidra 11.4.2 headless, Ghidriff 1.0.0 (with Ghidra's bundled pyghidra 2.2.1), BinExport (BinDiff 8 build) + BinDiff 8,
QBinDiff 1.2.3 (isolated interpreter). On the bundled demo dataset, STANDARD (Ghidra + Ghidriff + ACET matcher) gives
precision 1.0, recall 0.89, false-new 0, lineage purity 1.0 — see [`benchmarks/`](benchmarks/).

### Release readiness: not 1.0 / STABLE yet
The STABLE release gate (`tools/release_evidence.py check --channel STABLE`) validates the *content* of every
proof — Ed25519 signature of the release manifest by a trusted key, evidence pinned by that signature, test and
migration reports derived from the real JUnit run, each automated acceptance criterion backed by passing tests,
each manual criterion backed by an executed protocol result for this installer, triaged vulnerability scan of this
SBOM, approved license audit, benchmark gates against committed baselines. It currently (correctly) refuses STABLE
because these items are still open and need people, not code:

- **License audit sign-off** — [`docs/license-audit.json`](docs/license-audit.json) is complete except the ACET EULA
  (no text exists yet) and the legal approval (approver + date). `python tools/license_audit.py check` lists them.
- **Manual acceptance on real Windows machines** — ACC-001, 025, 056, 100, 150 and the Windows 10/11 clean-VM
  installs, recorded as described in [`release-inputs/README.md`](release-inputs/README.md).
- **Signing material** — Authenticode certificate and Ed25519 release key as CI secrets, release public key added
  to `src/acet/platform/trusted_keys.json` (the only place a release or update key can come from:
  [ADR-0011](docs/adr/0011-trust-store-policy.md)).
- **Advisory database + triage** for the vulnerability scan of the release SBOM.
- **Live engines in the release run** — the release runner must have the Engine Pack (`ACET_GHIDRA_DIR`, …):
  the live-engine tests behind ACC-026/038 are skipped without it, and the gate refuses skipped evidence.

### What has *not* been verified here
Windows-only paths were written to the spec but could not be executed in this Linux environment: the Job Object
wrapper, DPAPI secrets, `SetThreadExecutionState`, the PyInstaller/Inno Setup build, code signing and clean-VM
installs. They are exercised by the Windows CI matrix and the manual protocols.

## Quick start

```bash
python -m pip install -e ".[dev]"            # core is stdlib-only; the extras add tests + PySide6
acet workspace create demo                    # prints the workspace path
export ACET_WORKSPACE=<printed path>
acet product create "Fictional Guard"
acet import datasets/demo/builds/v1 --product "Fictional Guard" --release v1 --observed-at 2026-01-01
acet import datasets/demo/builds/v2 --product "Fictional Guard" --release v2 --observed-at 2026-02-01
acet analyze <build-id> --profile FAST@1
acet compare <left-build> <right-build> --profile STANDARD@1     # needs Ghidra (Engine Pack)
acet changes <run-id>                         # separate dimensions, no global score
acet lineage --product "Fictional Guard"
acet export <run-id> --format html
acet doctor --full                            # includes the golden self-test
acet-ui                                       # desktop UI
```

Engines come from a signed **Engine Pack** (Ghidra + private Java 21 runtime + Ghidriff interpreter), managed by
the Engine Pack Manager ([ADR-0013](docs/adr/0013-engine-pack-manager.md)): the `Engines` button in the top bar,
*Settings → Analysis Engines*, or `acet engines status|install [--file F]|verify|repair|rollback|recover`.
Nothing is downloaded without consent, every package (downloaded or local) is signature- and hash-checked,
installation is atomic, and a pack is READY only after the real `doctor --full` self-test ran on it. Development
and test builds resolve the signed **dev channel** (`src/acet/platform/distribution.json`; Windows x64 pack built by
`.github/workflows/engine-pack.yml` from `packaging/engine-pack/win64/recipe.json`); the same `.acetengine` can be
installed with *Install from file…*. A STABLE release refuses the dev channel and its key. A workspace can still pin
a pack (`engines.pinned_pack`). For
development: `ACET_GHIDRA_DIR`, `ACET_BINDIFF` and
`ACET_QBINDIFF_PYTHON`. Without engines ACET runs FAST and reports **DEGRADED**. CI without engines uses the
**golden replay** provider (`ACET_GHIDRA_REPLAY_DIR=datasets/demo/golden/ghidra`), which serves recorded real
Ghidra exports and is always reported as unverified.

CLI exit codes: `0` success · `10` partial success · `20` user error · `30` analysis failure · `40` system failure.

## Documentation
- ADRs: [`docs/adr/`](docs/adr) · threat model: [`docs/threat-model.md`](docs/threat-model.md) ·
  license audit: [`docs/license-audit.md`](docs/license-audit.md) · recovery runbook: [`docs/runbook.md`](docs/runbook.md)
- 21-dimension subsystem checklists (§94): [`docs/closure/subsystem-checklists.json`](docs/closure/subsystem-checklists.json)
- Demo dataset (original code, ground truth from linker maps): [`datasets/demo/`](datasets/demo)
- Capacity evidence (class M: 250 builds / 1M functions): [`docs/evidence/capacity-M.json`](docs/evidence/capacity-M.json)
- Engine Pack live run (Linux, real Ghidra/Java/Ghidriff): [`docs/evidence/engine-pack-e2e-linux.md`](docs/evidence/engine-pack-e2e-linux.md)

## Checks

```bash
ruff check src tests tools && ruff format --check src tests tools
mypy && mypy --platform win32                 # strict; the Windows-only branches are type-checked too
QT_QPA_PLATFORM=offscreen python -m pytest -q  # unit, property, integration, acceptance, UI
python tools/gen_traceability.py --check
pyinstaller packaging/acet.spec --noconfirm --distpath dist && python tools/frozen_smoke.py dist/ACET
ACET_GHIDRA_DIR=... ACET_BINDIFF=... ACET_QBINDIFF_PYTHON=... python -m pytest tests/integration/test_live_engines.py
```
