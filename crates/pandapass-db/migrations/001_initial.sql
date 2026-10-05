-- Create users table
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret_enc TEXT,  -- JSON encoded EncryptedSecret
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    recovery_codes_hash TEXT NOT NULL DEFAULT '[]',  -- JSON array of argon2 hashes
    global_role TEXT NOT NULL DEFAULT 'user',  -- 'admin' or 'user'
    created_at TEXT NOT NULL,
    disabled_at TEXT,
    last_login_at TEXT
);

-- Create projects table
CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Create project_members table
CREATE TABLE project_members (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,  -- 'owner', 'editor', 'viewer'
    added_by TEXT NOT NULL REFERENCES users(id),
    added_at TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id)
);

-- Create environments table
CREATE TABLE environments (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, slug)
);

-- Create secrets table
CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value_enc TEXT NOT NULL,  -- JSON encoded EncryptedSecret
    version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    UNIQUE(project_id, env_id, key)
);

-- Create secret_versions table (history)
CREATE TABLE secret_versions (
    id TEXT PRIMARY KEY,
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    value_enc TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

-- Create envelopes table (per-user encrypted master keys)
CREATE TABLE envelopes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,  -- base64 encoded age ciphertext
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    UNIQUE(user_id)
);

-- Create service_tokens table
CREATE TABLE service_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    env_id TEXT REFERENCES environments(id) ON DELETE SET NULL,
    scopes TEXT NOT NULL,  -- JSON array of scope strings
    expires_at TEXT,
    last_used_at TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

-- Create sessions table
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

-- Create audit_log table
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    user_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,
    project_id TEXT REFERENCES projects(id),
    env_id TEXT REFERENCES environments(id),
    secret_key TEXT,
    ip TEXT,
    user_agent TEXT,
    outcome TEXT NOT NULL,
    meta TEXT  -- JSON
);

-- Create indexes for performance
CREATE INDEX idx_project_members_user ON project_members(user_id);
CREATE INDEX idx_environments_project ON environments(project_id);
CREATE INDEX idx_secrets_project_env ON secrets(project_id, env_id);
CREATE INDEX idx_secrets_deleted ON secrets(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_secret_versions_secret ON secret_versions(secret_id);
CREATE INDEX idx_service_tokens_project ON service_tokens(project_id);
CREATE INDEX idx_audit_log_ts ON audit_log(ts DESC);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_project ON audit_log(project_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);