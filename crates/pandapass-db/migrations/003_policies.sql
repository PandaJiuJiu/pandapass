-- M3: Policy engine (OPA)

-- Policies table
CREATE TABLE policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    rego_source TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Policy bindings (project × environment × policy)
CREATE TABLE policy_bindings (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    env_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(policy_id, project_id, env_id)
);

CREATE INDEX idx_policy_bindings_policy ON policy_bindings(policy_id);
CREATE INDEX idx_policy_bindings_project_env ON policy_bindings(project_id, env_id);
