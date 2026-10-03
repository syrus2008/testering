ACET Engine Pack for Windows x64 — dev channel.

Contents: Ghidra 11.4.2, private Eclipse Temurin JDK 21.0.8+9 (ACET pins Ghidra to it; no system Java needed),
Ghidriff 1.0.0 on a private CPython 3.11.9 (pyghidra 2.2.1, JPype 1.5.2, mdutils 1.6.0). Licences and sources:
`licenses/THIRD-PARTY-NOTICES.txt` inside the pack.

Install from ACET: **Engines → Install Engine Pack** (dev/test builds resolve the signed index of this channel), or
download the `.acetengine` below and use **Install from file…** — both run the same checks: SHA-256 of the archive,
Ed25519 signature of the manifest (key `acet-dev-engines-2026-10`, dev channel only), every file's SHA-256, safe
extraction, live `doctor --full` health check, atomic activation.

Signed with a development key: STABLE releases of ACET do not trust it.
