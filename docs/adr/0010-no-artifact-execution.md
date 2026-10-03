# ADR-0010 — No artifact execution

- Status: Accepted
- Spec: ACET-PROD-002, ACET-IMP-001, ACET-SEC-001, INV-003, ACC-004

## Decision
No V1 workflow starts, loads, injects into or maps as executable any imported artifact. Format detection reads at
most the first 64 KiB of bytes and parses headers with `struct` (`acet.ingest.classify`).

Enforcement:
- A static test forbids process-spawning or code-loading primitives (`subprocess`, `ctypes`, `os.system`,
  `eval`, …) anywhere outside `acet.engines`/`acet.jobs`. Those packages launch *providers* such as Ghidra.
  They never launch artifacts.
- Providers receive artifacts as read-only data inputs inside an isolated workdir.
- Test fixtures are synthetic header-only PE byte strings with no code (`tests/fixtures.py`).
