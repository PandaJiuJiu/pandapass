-- M4: PKI/CA and SSH certificates

-- CA keys table
CREATE TABLE ca_keys (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,  -- 'root', 'intermediate'
    key_enc TEXT NOT NULL,  -- JSON encoded EncryptedSecret
    cert_pem TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

-- SSH certificates table
CREATE TABLE ssh_certs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    principal TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    key_type TEXT NOT NULL,  -- 'rsa', 'ed25519'
    valid_before TEXT NOT NULL,
    valid_after TEXT NOT NULL,
    revoked_at TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE INDEX idx_ssh_certs_user ON ssh_certs(user_id);
CREATE INDEX idx_ssh_certs_project ON ssh_certs(project_id);
CREATE INDEX idx_ssh_certs_valid ON ssh_certs(valid_before, valid_after) WHERE revoked_at IS NULL;
