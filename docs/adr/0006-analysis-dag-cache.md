# ADR-0006 — Analysis DAG and cache invalidation

- Status: Accepted (key function implemented; DAG roadmap P3/P4)
- Spec: §15, §27, ACET-ANA-003/004, ACET-CACHE-001, ACET-CON-001, INV-010

## Decision
- `cache_key = SHA256(canonical_json([processor_id, processor_version, ordered_input_hashes, config_hash,
  feature_schema_version]))`. A JSON array is used instead of string concatenation so the encoding is unambiguous
  (`acet.domain.cache.cache_key`).
- A cache hit requires exact key identity. A processor version change marks its descendants STALE. They stay
  readable and are never deleted.
- Single-flight: one computation per cache key. Concurrent requests wait for that computation and reuse its result.
- Derived outputs are written to `derived/<processor>/<version>/<cache-key>/` through temp + atomic rename.
