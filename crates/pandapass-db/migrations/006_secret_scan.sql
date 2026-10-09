-- M4: Secret scanning results.
--
-- One row per detected secret match. Deliberately stores NO plaintext: only
-- the secret's key name, the rule that fired, and the byte offsets of the
-- match inside the scanned value. This is the same contract the audit log
-- follows (key name yes, value never).
--
-- A scan run replaces the whole table (MVP semantics: the UI always shows the
-- latest scan), so there is no scan_run id — findings are ephemeral.

CREATE TABLE scan_findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    secret_key TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    match_start INTEGER NOT NULL,
    match_end INTEGER NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE INDEX idx_scan_findings_project_env ON scan_findings(project_id, env_id);
CREATE INDEX idx_scan_findings_severity ON scan_findings(severity);
CREATE INDEX idx_scan_findings_detected_at ON scan_findings(detected_at);