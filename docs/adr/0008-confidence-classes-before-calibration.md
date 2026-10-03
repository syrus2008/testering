# ADR-0008 — Confidence classes before calibration

- Status: Accepted
- Spec: §20, §67, ACET-BEN-003, ACET-SCI-001/002, INV-012, ACC-028/069/146

## Decision
Until an empirical, context-stratified calibration exists, the UI and reports show **classes** only
(`ConfidenceClass`: HIGH/MEDIUM/LOW/UNKNOWN; `MatchState`; `InferenceState`), never a percentage. Raw scores are
always stored (`matcher_result.raw_score`) and stay accessible. A context outside the calibrated domain is
`OUT_OF_DISTRIBUTION` and may force ABSTAIN. No global "magic score" merges anomaly dimensions.
