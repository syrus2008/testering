-- ACET migration 0003 — matching, consensus, lineage, baselines, calibration, benchmark, search (P5–P11).

ALTER TABLE function_instance ADD COLUMN derived_result_id TEXT NULL REFERENCES derived_result(id);
CREATE UNIQUE INDEX ux_function_instance_derived_addr ON function_instance(derived_result_id, address);
CREATE INDEX ix_function_instance_normalized ON function_instance(normalized_hash);
CREATE INDEX ix_function_instance_name ON function_instance(name);

ALTER TABLE matcher_result ADD COLUMN left_artifact_sha256 TEXT NULL;
ALTER TABLE matcher_result ADD COLUMN right_artifact_sha256 TEXT NULL;
ALTER TABLE matcher_result ADD COLUMN families_json TEXT NULL;

-- Consensus output per analysis run (§21). Immutable once written (INV-011).
CREATE TABLE consensus_match (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    left_artifact_sha256 TEXT NOT NULL REFERENCES artifact(sha256),
    right_artifact_sha256 TEXT NOT NULL REFERENCES artifact(sha256),
    left_function_id TEXT NULL REFERENCES function_instance(id),
    right_function_id TEXT NULL REFERENCES function_instance(id),
    decision TEXT NOT NULL,
    strength_class TEXT NOT NULL,
    evidence_diversity INTEGER NOT NULL,
    engine_count INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    calibration_profile_id TEXT NULL,
    rules TEXT NOT NULL
);
CREATE INDEX ix_consensus_run ON consensus_match(analysis_run_id, decision);
CREATE INDEX ix_consensus_left ON consensus_match(left_function_id);
CREATE TRIGGER consensus_match_immutable BEFORE UPDATE ON consensus_match
BEGIN SELECT RAISE(ABORT, 'consensus_match is immutable'); END;

-- Lineage (§22): assignments are bound to the lineage run and the build they describe.
ALTER TABLE lineage_assignment ADD COLUMN build_id TEXT NULL REFERENCES build(id);
ALTER TABLE lineage_assignment ADD COLUMN component_role TEXT NULL;
ALTER TABLE lineage_assignment ADD COLUMN evidence_json TEXT NULL;
ALTER TABLE lineage ADD COLUMN component_role TEXT NULL;
ALTER TABLE lineage ADD COLUMN label TEXT NULL;
CREATE INDEX ix_lineage_assignment_fn ON lineage_assignment(function_instance_id);
CREATE INDEX ix_lineage_assignment_run_build ON lineage_assignment(analysis_run_id, build_id);
CREATE TABLE lineage_link (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    parent_lineage_id TEXT NOT NULL REFERENCES lineage(id),
    child_lineage_id TEXT NOT NULL REFERENCES lineage(id),
    relation TEXT NOT NULL CHECK (relation IN ('SPLIT_PARENT','MERGE_PARENT','RESURRECTED_CANDIDATE')),
    build_id TEXT NULL REFERENCES build(id),
    evidence_json TEXT NOT NULL
);
CREATE TRIGGER lineage_link_immutable BEFORE UPDATE ON lineage_link
BEGIN SELECT RAISE(ABORT, 'lineage_link is immutable'); END;

-- Historical baselines (§24): per product/component/metric, never shared across products.
CREATE TABLE baseline_observation (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES product(id),
    component_role TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL NOT NULL,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    seq INTEGER NOT NULL
);
CREATE INDEX ix_baseline ON baseline_observation(product_id, component_role, metric, seq);
ALTER TABLE detected_change ADD COLUMN dimension TEXT NULL;
ALTER TABLE detected_change ADD COLUMN measurement_state TEXT NULL;
ALTER TABLE detected_change ADD COLUMN component_role TEXT NULL;
ALTER TABLE detected_change ADD COLUMN cluster_id TEXT NULL;

-- Calibration (§67): bound to a context and a dataset; never global.
CREATE TABLE calibration_profile (
    id TEXT PRIMARY KEY,
    engine TEXT NOT NULL,
    context_key TEXT NOT NULL,
    context_json TEXT NOT NULL,
    dataset_hash TEXT NOT NULL,
    split TEXT NOT NULL,
    method TEXT NOT NULL,
    mapping_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    validated INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX ix_calibration_ctx ON calibration_profile(engine, context_key);

-- Benchmark Lab (§39). Ground truth lives outside analysed inputs (ACET-BEN-001).
CREATE TABLE benchmark_dataset (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    dataset_hash TEXT NOT NULL UNIQUE,
    license TEXT NOT NULL,
    ground_truth_relpath TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE benchmark_run (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES benchmark_dataset(id),
    profile_ref TEXT NOT NULL,
    split TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Human review (§116): assertions never mutate automatic results.
CREATE TABLE human_assertion (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    assertion TEXT NOT NULL,
    reason TEXT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    author_id TEXT NULL,
    created_at TEXT NOT NULL
);

-- Full-text search for annotations (§108); rebuildable from canonical tables (ACET-SRCH-001).
CREATE VIRTUAL TABLE annotation_fts USING fts5(body, annotation_id UNINDEXED, tokenize = 'unicode61');

-- Purge bookkeeping (ACET-RET-001)
ALTER TABLE artifact ADD COLUMN purged_at TEXT NULL;
CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL);
