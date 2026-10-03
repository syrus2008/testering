-- ACET migration 0001_initial — normative schema of spec §9/§10.
-- Additions beyond the "minimal columns" are marked with the requirement that motivates them.
-- Timestamps are UTC ISO-8601 TEXT (ACET-TIME-002). NULL = unknown/not measured (ACET-DATA-002).

CREATE TABLE workspace (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    schema_version INTEGER NOT NULL
);

CREATE TABLE product (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspace(id),
    name TEXT NOT NULL,
    vendor TEXT NULL,
    profile_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE release (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES product(id),
    version_label TEXT NOT NULL,
    channel TEXT NULL,
    release_date TEXT NULL,
    notes TEXT NULL,
    UNIQUE (product_id, version_label, channel)
);

CREATE TABLE build (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES product(id),
    release_id TEXT NULL REFERENCES release(id),
    build_fingerprint TEXT NOT NULL UNIQUE CHECK (length(build_fingerprint) = 64),
    arch TEXT NULL,
    platform TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('COMPLETE', 'PARTIAL', 'UNASSESSED')),
    created_at TEXT NOT NULL,
    deleted_at TEXT NULL  -- ACET-RET-001 / ACC-036: soft delete -> Trash
);

CREATE TABLE observation (
    id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES build(id),
    observed_at TEXT NULL,
    time_precision TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_label TEXT NULL,  -- never a full local path (ACET-PRI-001)
    imported_at TEXT NOT NULL
);

CREATE TABLE component (
    id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES build(id),
    role TEXT NOT NULL,
    role_confidence TEXT NOT NULL,
    label TEXT NULL,
    ordinal INTEGER NOT NULL
);

CREATE TABLE artifact (
    sha256 TEXT PRIMARY KEY CHECK (length(sha256) = 64 AND sha256 = lower(sha256)),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    mime_hint TEXT NULL,
    format TEXT NOT NULL,
    arch TEXT NULL,
    store_relpath TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    integrity_state TEXT NOT NULL CHECK (integrity_state IN
        ('DISCOVERED','HASHING','COPYING','VERIFYING','AVAILABLE','CORRUPTED','ORPHANED','QUARANTINED','PURGED'))
);

CREATE TABLE component_artifact (
    component_id TEXT NOT NULL REFERENCES component(id),
    artifact_sha256 TEXT NOT NULL REFERENCES artifact(sha256),
    purpose TEXT NOT NULL,
    PRIMARY KEY (component_id, artifact_sha256, purpose)
);

-- Human correction of an automatic classification is stored separately (§13).
CREATE TABLE role_assertion (
    id TEXT PRIMARY KEY,
    component_id TEXT NOT NULL REFERENCES component(id),
    role TEXT NOT NULL,
    author_id TEXT NULL,
    reason TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE analysis_profile (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    config_hash TEXT NOT NULL UNIQUE,
    UNIQUE (name, version)
);

CREATE TABLE engine_pack (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE analysis_run (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    profile_id TEXT NOT NULL REFERENCES analysis_profile(id),
    engine_pack_id TEXT NULL REFERENCES engine_pack(id),  -- NULL for engine-less profiles (FAST)
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NULL,
    coverage REAL NULL,
    resolved_config_json TEXT NULL,  -- ACET-CFG-001
    resolved_config_hash TEXT NULL
);

CREATE TABLE processor_run (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    processor_id TEXT NOT NULL,
    processor_version TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NULL,
    outcome TEXT NULL,          -- OperationOutcome (ACET-CLOSE-002)
    failure_family TEXT NULL,   -- FailureFamily (ACC-103)
    determinism_class TEXT NULL -- ACET-DET-001
);

CREATE TABLE function_instance (
    id TEXT PRIMARY KEY,
    artifact_sha256 TEXT NOT NULL REFERENCES artifact(sha256),
    extractor_run_id TEXT NOT NULL REFERENCES processor_run(id),
    address INTEGER NOT NULL,
    size INTEGER NOT NULL,
    name TEXT NULL,
    normalized_hash TEXT NULL,
    feature_schema_version INTEGER NOT NULL,
    normalizer_version TEXT NULL  -- ACET-MAT-001
);

CREATE TABLE matcher_result (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    engine TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    left_function_id TEXT NULL REFERENCES function_instance(id),
    right_function_id TEXT NULL REFERENCES function_instance(id),
    raw_score REAL NULL,
    calibrated_strength REAL NULL,
    decision TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);

CREATE TABLE lineage (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES product(id),
    created_by_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    status TEXT NOT NULL
);

CREATE TABLE lineage_assignment (
    id TEXT PRIMARY KEY,
    lineage_id TEXT NOT NULL REFERENCES lineage(id),
    function_instance_id TEXT NOT NULL REFERENCES function_instance(id),
    analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    relation TEXT NOT NULL,
    strength REAL NULL,
    status TEXT NOT NULL
);

CREATE TABLE detected_change (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_run(id),
    change_type TEXT NOT NULL,
    severity_class TEXT NOT NULL,
    reliability_class TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);

CREATE TABLE external_event (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES product(id),
    event_type TEXT NOT NULL,
    occurred_at TEXT NULL,
    time_precision TEXT NOT NULL,
    source_class TEXT NOT NULL CHECK (source_class IN ('OFFICIAL','RESEARCH','COMMUNITY','LOCAL_NOTE')),
    source_ref TEXT NULL,
    summary TEXT NOT NULL,
    recorded_at TEXT NOT NULL,          -- ACET-EVT-001
    corroboration TEXT NOT NULL DEFAULT 'UNCORROBORATED'  -- ACET-EVT-001
);

CREATE TABLE annotation (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    author_id TEXT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    deleted_at TEXT NULL
);

CREATE TABLE job (
    id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    analysis_run_id TEXT NULL REFERENCES analysis_run(id),
    state TEXT NOT NULL,
    priority INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    checkpoint_json TEXT NULL,
    error_code TEXT NULL
);

-- Append-oriented (§76). A trigger forbids UPDATE/DELETE.
CREATE TABLE audit_event (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    target_type TEXT NULL,
    target_id TEXT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TRIGGER audit_event_no_update BEFORE UPDATE ON audit_event
BEGIN SELECT RAISE(ABORT, 'audit_event is append-only'); END;
CREATE TRIGGER audit_event_no_delete BEFORE DELETE ON audit_event
BEGIN SELECT RAISE(ABORT, 'audit_event is append-only'); END;

-- INV-011 / ACET-LIN-001: historical analysis rows are immutable once written.
CREATE TRIGGER matcher_result_immutable BEFORE UPDATE ON matcher_result
BEGIN SELECT RAISE(ABORT, 'matcher_result is immutable (ACET-MAT-003)'); END;
CREATE TRIGGER lineage_assignment_immutable BEFORE UPDATE ON lineage_assignment
BEGIN SELECT RAISE(ABORT, 'lineage_assignment is immutable (ACET-LIN-001)'); END;

-- §10 constraints and indexes
CREATE INDEX ix_observation_build_observed ON observation(build_id, observed_at);
CREATE INDEX ix_component_build_role ON component(build_id, role);
CREATE INDEX ix_function_instance_artifact_address ON function_instance(artifact_sha256, address);
CREATE INDEX ix_matcher_result_run_engine_decision ON matcher_result(analysis_run_id, engine, decision);
CREATE INDEX ix_lineage_assignment_lineage_run ON lineage_assignment(lineage_id, analysis_run_id);
CREATE INDEX ix_job_state_priority_created ON job(state, priority, created_at);
CREATE INDEX ix_external_event_product_occurred ON external_event(product_id, occurred_at);
CREATE INDEX ix_component_artifact_sha ON component_artifact(artifact_sha256);
CREATE INDEX ix_build_product ON build(product_id);
