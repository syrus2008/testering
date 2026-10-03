# Resurrection corpus (`acet-resurrection@1`)

Original code (same license as ACET), built with clang + lld-link: `python datasets/resurrection/build.py`
(reproducible: fixed object names, `/brepro`). One x64 DLL, `rescore.dll`, in five builds. Each scenario
is the sequence `v1 → v2 → v3_<x>`; `audit_record` exists in v1, is removed in v2 and:

| Scenario | v3 | Expected (`resurrect@2`) |
|---|---|---|
| `identical` | `audit_record` back, same source and flags | historical lineage reused (`RESURRECTED_CONFIRMED`) |
| `recompiled` | same source, its unit built `-O2 -fno-omit-frame-pointer` | confirmed only because code, data and caller context converge |
| `recompiled_heavy` | same source, `-O3 -march=haswell` (unrolled, 190 instructions vs 35) | linked hypothesis only (`RESURRECTED_CANDIDATE`): the code no longer supports continuity |
| `lookalike` | `audit_record` still absent; `trace_record` appears: **same normalized code** and callee, different constants, different caller | never merged, never even proposed (data contradiction) |

`ground_truth.json` comes from the linker maps; `golden/ghidra/` holds real Ghidra 11.4.2 exports
recorded with `tools/record_golden.py` (CI replays them). Tests: `tests/integration/test_resurrection_corpus.py`;
results: `benchmarks/resurrection-STANDARD@1-*.json` (`tools/run_benchmarks.py`).
