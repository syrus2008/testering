# ADR-0001 — Layered architecture

- Status: Accepted
- Spec: §4, §5, ACET-ARCH-001..003

## Context
ACET must be testable headless, survive engine crashes, and keep a desktop UI responsive.

## Decision
Layers, top to bottom: `acet.ui` (PySide6) → `acet.application` (use cases, transactions) → `acet.domain`
(pure rules) → `acet.analysis` (DAG) → `acet.jobs` (supervisor) → engine workers (separate processes) →
`acet.storage` (SQLite, content store). `acet.cli` sits beside the UI and calls the same application services.

- `acet.domain` imports neither Qt, SQLite nor the filesystem.
- Only `acet.ui` may import PySide6. Enforced by `tests/unit/test_domain.py::test_domain_is_pure_and_headless`.
- The Core runtime is standard-library only, so it can ship as an embedded runtime and run offline.
- Core ↔ worker boundaries use versioned, schema-validated DTOs (`schemas/v1/worker-*.schema.json`).

## Consequences
Every use case is reachable from the CLI (CLI parity, ACC-042). The UI can be built last (P13) without
rewriting business logic.
