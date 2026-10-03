# ADR-0012 — Graded resurrection (`resurrect@2`, `lineage@2`)

- Status: Accepted
- Spec: ACET-LIN-001/002 (§22), §21 (independent evidence families), ACC-018/019

## Context
`lineage@1` turned every return of a disappeared function into `RESURRECTED_CANDIDATE`: a *new* lineage linked
to the old one. That never merges wrongly, but a function that comes back unchanged lost its history, and one
matcher score (≥ 0.75) was the only evidence — a lookalike with the same normalized code (normalization strips
constants) became a candidate too.

## Decision
`acet.lineage.resurrection` grades each (returning function, disappeared lineage) pairing from independent families:
code (`exact` non-trivial / `similar` at the matcher's STRONG class), data (strings/constants), caller context
(lineages of callers at the last appearance vs. now), real symbol names, a recorded ROLLBACK event.

- **CONFIRMED** (function assigned to the *historical* lineage, relation `RESURRECTED_CONFIRMED`): caller context
  **and** `code=exact`, or caller context and `code=similar` and one more family; no contradiction; mutual-best
  pairing with a 0.05 margin (otherwise downgraded).
- **CANDIDATE** (new lineage + `RESURRECTED_CANDIDATE` link, as before): code evidence, matcher score ≥ 0.75, or
  data and context both supporting.
- **REJECTED**: any contradicting family (data Jaccard < 0.3 on non-trivial sets, different real names) — the
  refused hypothesis is kept in the evidence of the `UNRESOLVED` assignment.
- Trivial code (< 8 instructions) is not code evidence; callees alone are not context (shared helpers).

## Measurement (STANDARD@1; `tools/run_benchmarks.py`, files in `benchmarks/`)
Resurrection corpus (`datasets/resurrection`, real binaries; replay and live Ghidra give the same verdicts):

| Scenario | `lineage@1` | `lineage@2` |
|---|---|---|
| identical return | candidate (history split) | **confirmed**: code exact + data + context |
| recompiled (-O2) | candidate | **confirmed**: code similar + data + context |
| recompiled heavy (-O3, 190 vs 35 insns) | **lost** (no link) | linked candidate (data + context) |
| lookalike (same normalized code, other constants and caller) | **false candidate** | rejected (data contradiction) |
| purity / wrong merge, all scenarios | 1.0 / 0 | 1.0 / 0 |
| unexplained fragmentation (heavy) | 0.2 | 0.0 |
| false resurrection candidates (lookalike) | 1 | 0 |

Reference measurement before the change: `benchmarks/reference/resurrection-STANDARD@1-replay-lineage1.json`.

Demo dataset: unchanged by the new rule (purity 1.0, wrong merge 0). Its returning function (`report_event`)
has the same *source* but not the same machine code (dead stores removed in v1: 5 vs 27 instructions, no data
references), so only caller context agrees — ACET correctly makes no claim. The demo ground truth now links that
resurrection (it previously treated v1 and v3 as different functions, which would have scored a correct
re-attachment as a wrong merge); strict fragmentation therefore reads 0.2381 (replay) / 0.1905 (live) instead of
0.1818 / 0.1364 — same lineages, corrected reference.

## Metrics added (`lineage_metrics`)
Strict metrics are unchanged. Added: `wrong_split_linked` / `wrong_split_unlinked` (fragmentation ACET explained
with a recorded split/merge/resurrection link vs. lost history), `fragmentation_unlinked`,
`multi_version_recovery_linked`, `resurrections` {confirmed, candidate_linked, missed} and
`false_resurrection_candidates`. Regression gates treat wrong merges, unexplained splits and false candidates as
lower-is-better; the corpus baselines allow **zero** tolerance on purity, wrong merges and false candidates, so
recovery can never be bought with purity.

## Remaining gaps
Demo v2→v3 losses `policy_decide` and `mainCRTStartup` are matcher recall misses (code changed a lot), not
resurrections. The corpus is small and clang-only; a compiler/optimisation/LTO/stripping matrix is the next step.

## Reporting and UI (closure pass)
- One vocabulary, `acet.reporting.vocabulary`, decides each claim's inference level (`INFERENCE_RANK`, weakest
  `NOT_OBSERVED`/`UNRESOLVED` → `HYPOTHESIS` → `PROBABLE` → `STRONG` → `CONFIRMED_BY_RULE`) and its wording. The report
  model writes `inference_state`, `status_text` and `explanation`; Markdown, HTML, CSV and the UI only transcribe them.
- Report model: `technical.lineage.events` — the lineage events of the compared transition (historical lineage,
  instance, relation, rule, supporting/contradicting families, reasons, explanation, decision, provenance:
  lineage run, rules, compare run). Split/merge links and resurrection candidates are `HYPOTHESIS`;
  `RESURRECTED_CONFIRMED` carries "Historical identity reused because …"; rejected resurrections stay visible.
- Executive summary counts confirmed resurrections and candidates, calling candidates hypotheses.
- `executive.completeness`: `COMPLETED_PARTIAL` (or any missing evidence) opens Markdown/HTML with a banner listing the
  missing evidence and stating that missing evidence is not negative evidence; the Compare and Changes pages show
  the same banner. Function rows carry the calibration state (`UNCALIBRATED` / `OUT_OF_DISTRIBUTION` /
  `CALIBRATED`); probabilities stay null. External events carry "temporal correlation only, not a cause".
- `invariant_problems()` runs on every report: a model that overstates (candidate shown confirmed, candidate
  presented as fact in the executive summary, partial run not flagged, printed probability) is refused.
- Lineage UI: history rows show inference and statement; the Evidence Inspector shows the same text as the report
  (hypotheses headed "⚠ HYPOTHESIS — NOT ESTABLISHED"); hypothesis nodes are drawn differently in the graph.
- Tests: `tests/integration/test_report_fidelity.py` (terms survive model → JSON/MD/HTML/CSV; renderers transcribe
  inference exactly, property-based over random reports with hostile names — a manual mutation check confirmed that a renderer
  printing a hypothesis as CONFIRMED_BY_RULE fails these tests), `tests/ui/test_lineage_inspector.py`. Matcher and lineage
  thresholds were not changed.
