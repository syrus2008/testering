# Security policy

ACET analyses potentially hostile binaries. Its core guarantee is that **no imported artifact is ever executed**
(ADR-0010).

## Reporting a vulnerability
Report privately to the repository owner. Do not open a public issue. Include the ACET version, the steps to
reproduce, and the output of `acet doctor --json`. Do not attach artifact bytes unless you are asked to.

## Scope
Bypasses of the no-execution guarantee, path traversal, archive/pack extraction escapes, store or DB
integrity bypasses, tampered Engine Pack or update acceptance, and leakage of local paths or artifact content.

## Process (ACET-VULN-001)
Triage looks at exploitability in ACET's context, not only CVSS. Fixes ship as a new app or Engine Pack. A
compromised provider is added to the update denylist (ACET-SUP-005), and historical results that reference it are
kept with a provenance banner.
