"""Engine adapters (Ghidra, Ghidriff, BinExport/BinDiff, QBinDiff, external Diaphora) and the generic worker.

This package — with ``acet.jobs`` — is the only place allowed to start processes.
It starts *providers*, never analysed artifacts (ADR-0010)."""
