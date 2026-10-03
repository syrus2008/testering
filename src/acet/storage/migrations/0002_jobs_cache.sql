-- ACET migration 0002 — jobs, locks, derived-result cache index, run provenance (roadmap P3/P4).

-- Derived results cache index (ACET-ANA-004, §27, INV-010). One row per cache key.
CREATE TABLE derived_result (
    id TEXT PRIMARY KEY,
    cache_key TEXT NOT NULL CHECK (length(cache_key) = 64),
    processor_id TEXT NOT NULL,
    processor_version TEXT NOT NULL,
    determinism_class TEXT NOT NULL CHECK (determinism_class IN ('D0','D1','D2','D3')),
    state TEXT NOT NULL CHECK (state IN ('CURRENT','STALE','INCOMPLETE','FAILED','CORRUPTED')),
    output_relpath TEXT NOT NULL,
    output_sha256 TEXT NOT NULL CHECK (length(output_sha256) = 64),
    produced_by_processor_run_id TEXT NOT NULL REFERENCES processor_run(id),
    created_at TEXT NOT NULL,
    stale_reason TEXT NULL
);
CREATE INDEX ix_derived_result_processor ON derived_result(processor_id, processor_version, state);
-- At most one CURRENT result per cache key; older INCOMPLETE/FAILED/STALE attempts are kept (INV-011).
CREATE UNIQUE INDEX ux_derived_result_current ON derived_result(cache_key) WHERE state = 'CURRENT';
CREATE INDEX ix_derived_result_key ON derived_result(cache_key);

-- Provenance edges of derived results (needed for selective STALE propagation, ACET-ANA-003).
CREATE TABLE derived_input (
    derived_result_id TEXT NOT NULL REFERENCES derived_result(id),
    ordinal INTEGER NOT NULL,
    input_kind TEXT NOT NULL CHECK (input_kind IN ('artifact','derived')),
    input_ref TEXT NOT NULL,
    PRIMARY KEY (derived_result_id, ordinal)
);
CREATE INDEX ix_derived_input_ref ON derived_input(input_kind, input_ref);

ALTER TABLE processor_run ADD COLUMN derived_result_id TEXT NULL REFERENCES derived_result(id);
ALTER TABLE processor_run ADD COLUMN node_key TEXT NULL;
ALTER TABLE processor_run ADD COLUMN termination TEXT NULL;
ALTER TABLE processor_run ADD COLUMN completion_state TEXT NULL;
ALTER TABLE processor_run ADD COLUMN warnings_json TEXT NULL;
ALTER TABLE processor_run ADD COLUMN metrics_json TEXT NULL;
ALTER TABLE processor_run ADD COLUMN error_code TEXT NULL;
ALTER TABLE processor_run ADD COLUMN cache_hit INTEGER NOT NULL DEFAULT 0;
CREATE INDEX ix_processor_run_run ON processor_run(analysis_run_id);

ALTER TABLE analysis_run ADD COLUMN missing_evidence_json TEXT NULL;
ALTER TABLE analysis_run ADD COLUMN coverage_json TEXT NULL;
ALTER TABLE analysis_run ADD COLUMN warnings_json TEXT NULL;
ALTER TABLE analysis_run ADD COLUMN input_hashes_json TEXT NULL;
ALTER TABLE analysis_run ADD COLUMN acet_version TEXT NULL;
ALTER TABLE analysis_run ADD COLUMN seq INTEGER NULL;  -- causal order (ACET-TIME-001), not wall clock

ALTER TABLE job ADD COLUMN payload_json TEXT NULL;
ALTER TABLE job ADD COLUMN stage TEXT NULL;
ALTER TABLE job ADD COLUMN progress REAL NULL;
ALTER TABLE job ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE job ADD COLUMN owner_pid INTEGER NULL;
ALTER TABLE job ADD COLUMN owner_host TEXT NULL;
ALTER TABLE job ADD COLUMN heartbeat_at TEXT NULL;
ALTER TABLE job ADD COLUMN seq INTEGER NULL;

-- Application locks with owner identification (ACET-CON-001/002).
CREATE TABLE app_lock (
    name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    owner_pid INTEGER NOT NULL,
    owner_host TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL
);

-- Monotonic sequence for causal ordering independent from wall clock (FI-008, ACC-123).
CREATE TABLE sequence (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO sequence(name, value) VALUES ('global', 0);
