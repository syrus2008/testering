# License audit (spec §45, §113, ACET-LIC-001)

No third-party binary may enter an installer or Engine Pack until its row below is complete and reviewed.

| Component | Version audited | SPDX | Redistribution | Bundling decision | Notes |
|---|---|---|---|---|---|
| Python runtime | — | PSF-2.0 | yes | bundled (P12) | to audit at packaging |
| PySide6 | — | LGPL-3.0-only / commercial | conditional | bundled (P13) | LGPL obligations (relinking) to review |
| Ghidra | — | Apache-2.0 (+ third-party notices, some GPL) | conditional | Engine Pack | separate notices required |
| Ghidriff | — | GPL-3.0 | conditional | to decide | provider process boundary; audit before redistribution |
| BinDiff / BinExport | — | Apache-2.0 | yes | Engine Pack | pin exact versions |
| QBinDiff | — | Apache-2.0 | yes | Engine Pack (isolated venv) | experimental |
| Diaphora | — | AGPL-3.0 (≥2.0) | n/a | external only (ADR-0009) | requires IDA |
| Java runtime (for Ghidra) | — | GPL-2.0 WITH Classpath-exception-2.0 (OpenJDK) | conditional | Engine Pack | choose distribution |

The current repository ships **no** third-party binaries. The Core has no runtime dependencies beyond the Python standard library.
