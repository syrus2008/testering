# ACET — Anti-Cheat Evolution Tracker

ACET is a local, offline-first application for **longitudinal comparison of binary components**. It imports
user-supplied artifacts, groups them into builds and observations, extracts reproducible facts, matches functions
across versions, builds lineages, flags unusual changes, and produces inspectable reports. It **never executes**
an imported artifact.

The normative specification is [`docs/spec/ACET_Master_Specification_v3_FINAL.docx`](docs/spec/ACET_Master_Specification_v3_FINAL.docx)
(a text extract sits next to it). Requirement IDs (`ACET-*`, `ACC-*`, `INV-*`) in code and tests refer to it.

## Status

Implementation follows the locked roadmap (spec §56). This repository currently covers:

| Phase | Deliverable | State |
|---|---|---|
| P0 | Repo, packaging skeleton, domain conventions, typed contracts, CI | ✅ |
| P1 | Workspace, SQLite (WAL, FK, migrations, backup/restore), content-addressed store | ✅ |
| P2 | Import pipeline + CLI import (hostile-input matrix) | ✅ headless (wizard UI with P13) |
| P3 | Jobs / workers / checkpoints / Doctor | Doctor + reconcile only |
| P4–P13 | FAST facts, Ghidra, diff providers, consensus, lineage, changes, benchmark, reports/packs, installer, UI | not started |

Acceptance status for ACC-001..150 is generated from the test markers in
[`docs/traceability/acceptance-matrix.json`](docs/traceability/acceptance-matrix.json).

## Quick start (development)

```bash
python -m pip install -e ".[dev]"
acet workspace create demo                      # prints the workspace path
export ACET_WORKSPACE=<path printed above>
acet product create "My Product" --profile profile.json   # optional Product Profile v2
acet import ./build-1.0 --product "My Product" --release 1.0 --observed-at 2026-09-01
acet import ./build-1.1 --product "My Product" --release 1.1
acet builds list
acet builds verify <build-id>                   # integrity gate run before any analysis
acet doctor --full                              # READY / DEGRADED / ACTION_REQUIRED
acet reconcile --deep                           # DB ↔ store consistency (read-only)
acet backup                                     # WAL-aware hot metadata backup
```

CLI exit codes: `0` success · `10` partial success · `20` user error · `30` analysis failure · `40` system failure.

Workspaces live under `%LOCALAPPDATA%\ACET\workspaces\` on Windows. Set `ACET_HOME` to override.

## Layout

```
src/acet/
  domain/       pure rules: ids (UUIDv7), canonical JSON, fingerprint, state machines, taxonomies, error catalog
  storage/      SQLite service, migrations (0001_initial.sql), migrator, content store, repositories
  ingest/       discover (loop-safe), static classify (header-only PE parsing), import pipeline
  application/  workspace, product and build use cases
  platform/     paths, Doctor, reconcile
  cli/          official headless CLI
  analysis/ engines/ matching/ lineage/ changes/ jobs/ benchmark/ reporting/ ui/   (later phases)
schemas/v1/     JSON Schemas: worker protocol, completion manifest, provider/engine pack, .acetpack, product profile
docs/adr/       ADR-0001..0010
docs/           threat model, license audit, traceability
tests/          unit · property (Hypothesis) · integration · acceptance
tools/          gen_traceability.py
```

## Checks

```bash
ruff check src tests tools && ruff format --check src tests tools
mypy                        # strict, src/acet
python -m pytest -q
python tools/gen_traceability.py --check
```
