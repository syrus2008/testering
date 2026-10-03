-- ACET migration 0004 — purge bookkeeping and annotation search triggers (P11).

ALTER TABLE build ADD COLUMN purged_at TEXT NULL;  -- ACET-RET-001: purge is explicit and recorded

-- Keep the FTS index in sync with annotations (index is rebuildable, ACET-SRCH-001).
CREATE TRIGGER annotation_fts_ins AFTER INSERT ON annotation BEGIN
    INSERT INTO annotation_fts(body, annotation_id) VALUES (new.body, new.id);
END;
CREATE TRIGGER annotation_fts_del AFTER UPDATE OF deleted_at ON annotation WHEN new.deleted_at IS NOT NULL BEGIN
    DELETE FROM annotation_fts WHERE annotation_id = new.id;
END;
