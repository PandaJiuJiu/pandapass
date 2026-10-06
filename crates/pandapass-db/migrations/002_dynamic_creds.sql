-- M2: Dynamic credentials

-- Dynamic credentials table
CREATE TABLE dynamic_creds (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,  -- 'postgresql', 'mysql', 'redis'
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL,  -- JSON encoded EncryptedSecret
    ttl_seconds INTEGER NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_by TEXT NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_dynamic_creds_project_env ON dynamic_creds(project_id, env_id);
CREATE INDEX idx_dynamic_creds_expires ON dynamic_creds(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_dynamic_creds_revoked ON dynamic_creds(revoked_at) WHERE revoked_at IS NOT NULL;
