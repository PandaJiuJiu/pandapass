-- Audit log tamper-evidence (HMAC chain).
--
-- Every audit entry gets an `entry_hash`: HMAC-SHA256 over the previous
-- entry's hash plus this entry's canonical fields. Deleting or editing a
-- row breaks the chain for every entry after it, which `pandapass audit
-- verify` can detect.
--
-- Existing rows are backfilled with an empty string and are skipped by
-- verification; the chain effectively starts at the first new entry.

ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_audit_entry_hash ON audit_log(entry_hash);
