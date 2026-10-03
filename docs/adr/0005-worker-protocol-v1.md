# ADR-0005 — Worker protocol v1

- Status: Accepted (contract only; implementation roadmap P3)
- Spec: §52, §59, §60, ACET-ARCH-002/003, ACET-ENG-001..003, ACET-WIN-001..003

## Decision
- Engines run in separate processes. Each process tree is assigned to a Windows Job Object with kill-on-close.
  Cancellation is graceful first, then `TerminateJobObject` after a configurable delay.
- Request and response DTOs: `schemas/v1/worker-request.schema.json`, `worker-response.schema.json`.
- A worker is never trusted on its exit code alone. The Supervisor requires a completion manifest
  (`completion-manifest.schema.json`), checks the presence and checksums of the outputs and the counters,
  and runs the versioned log parser before declaring COMPLETED. Otherwise the result is PARTIAL or INVALID.
- stdout/stderr are drained to bounded, rotating files that keep the head, the tail and error counters.
- An incompatible `protocol_version` prevents launch (ACC-086).
