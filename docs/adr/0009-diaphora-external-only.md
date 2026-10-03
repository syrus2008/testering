# ADR-0009 — Diaphora is an external provider only

- Status: Accepted
- Spec: §17, §45, §90

## Decision
Diaphora depends on IDA (commercial, not shipped) and is AGPL-3.0 since 2.0. It is not part of any default Engine
Pack and is never required by STANDARD. ACET may detect a compatible installation and expose its capability as an
**unverified external provider**. Doctor reports it as "detection only".
