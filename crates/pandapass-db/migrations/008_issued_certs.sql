-- Track every certificate a CA has signed, so individual certs can
-- be revoked without revoking the CA (and every cert it has ever
-- issued). The serial_number is the X.509 RFC 5280 serial; stored as
-- a hex string so it survives the binary serial range cleanly.

CREATE TABLE issued_certs (
    id TEXT PRIMARY KEY,
    ca_id TEXT NOT NULL REFERENCES ca_keys(id) ON DELETE CASCADE,
    serial_number TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    revoked_at TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE INDEX idx_issued_certs_ca ON issued_certs(ca_id);
CREATE INDEX idx_issued_certs_valid ON issued_certs(not_after) WHERE revoked_at IS NULL;
