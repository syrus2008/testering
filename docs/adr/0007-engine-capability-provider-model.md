# ADR-0007 — Engine capability / provider model

- Status: Accepted (manifest schema; providers roadmap P5–P8)
- Spec: §17, §18, §68, §90, ACC-033

## Decision
Providers declare capabilities (DISASSEMBLY, FUNCTION_EXTRACTION, STRUCTURAL_DIFF, PROGRAMMABLE_DIFF,
SEMANTIC_FEATURES, REPORT_EXPORT) in `provider-manifest.schema.json`. Profiles and UI depend on capabilities,
never on provider names. A missing optional capability yields DEGRADED and COMPLETED_PARTIAL with
`missing_evidence`, never a global failure. Priority: Ghidra headless (mandatory), Ghidriff (primary diff),
BinExport+BinDiff (official structural cross-check), QBinDiff (experimental, memory-gated), Diaphora (external).
