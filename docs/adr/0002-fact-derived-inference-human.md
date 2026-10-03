# ADR-0002 — Fact / Derived / Inference / Human separation

- Status: Accepted
- Spec: §2, §6, INV-004, INV-005, INV-011, ACET-HUM-001

## Decision
Data falls into five categories, and each has its own mutability rule:

| Category | Mutability | Storage rule |
|---|---|---|
| SOURCE | immutable | content-addressed blob, read-only file |
| FACT | immutable | rows written once; a new extraction creates a new derived version |
| DERIVED | versioned | keyed by processor version + cache key |
| INTERPRETATION | versioned | bound to an `analysis_run`; never rewritten (`matcher_result`, `lineage_assignment` have UPDATE-forbidding triggers) |
| HUMAN | historized | annotations/assertions in separate tables; never mutate automatic results |

A human correction of a component role goes to `role_assertion`. It does not edit `component.role`.

## Consequences
Re-analysis appends and never overwrites (ACC-018, ACC-144). Human annotations never become benchmark
ground truth automatically (ACC-132).
