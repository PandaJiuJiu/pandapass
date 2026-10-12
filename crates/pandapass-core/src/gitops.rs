//! GitOps sync — pure logic layer.
//!
//! This module is intentionally IO-free: it computes the difference between the
//! local secrets file and the remote server state, so it can be unit-tested
//! without a database, HTTP client, or filesystem. The CLI commands in
//! `pandapass-cli` perform the actual IO and apply the diff.

use crate::models::{SecretMeta, SyncState};
use std::collections::HashMap;

/// A single secret's sync status between local and remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretDiffState {
    /// Present only in the local file (not on the server).
    OnlyLocal,
    /// Present only on the server (not in the local file).
    OnlyRemote,
    /// Present on both sides but the values differ.
    Modified,
    /// Present on both sides with the same value.
    InSync,
}

/// One row of a diff report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    pub key: String,
    pub state: SecretDiffState,
    /// Local version, if known
    pub local_version: Option<i32>,
    /// Remote version, if known
    pub remote_version: Option<i32>,
}

/// The full diff between a local file and remote state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffReport {
    pub entries: Vec<DiffEntry>,
}

impl DiffReport {
    pub fn only_local(&self) -> impl Iterator<Item = &DiffEntry> {
        self.entries
            .iter()
            .filter(|e| e.state == SecretDiffState::OnlyLocal)
    }
    pub fn only_remote(&self) -> impl Iterator<Item = &DiffEntry> {
        self.entries
            .iter()
            .filter(|e| e.state == SecretDiffState::OnlyRemote)
    }
    pub fn modified(&self) -> impl Iterator<Item = &DiffEntry> {
        self.entries
            .iter()
            .filter(|e| e.state == SecretDiffState::Modified)
    }
}

/// Compute the diff between a local secrets map and the remote secret metadata.
///
/// * `local` — plaintext secrets read from `.pandapass/secrets/<env>.yaml` (key -> value).
/// * `remote` — secret metadata returned by `list_secret_metas` (active secrets only).
///
/// Value comparison is done by *presence* rather than by comparing plaintext to
/// ciphertext: a key is `Modified` when it exists locally and remotely, and the
/// local sync state says the remote version changed since we last synced (or we
/// have no sync state at all, in which case it is conservatively `Modified`).
/// The caller decides how to treat a `Modified` row based on the sync state.
pub fn diff_metadata(
    local: &HashMap<String, String>,
    remote: &[SecretMeta],
    sync_state: &SyncState,
) -> DiffReport {
    let remote_by_key: HashMap<&str, &SecretMeta> =
        remote.iter().map(|m| (m.key.as_str(), m)).collect();

    let mut entries: Vec<DiffEntry> = Vec::new();

    // Local keys.
    for (key, _value) in local {
        match remote_by_key.get(key.as_str()) {
            None => entries.push(DiffEntry {
                key: key.clone(),
                state: SecretDiffState::OnlyLocal,
                local_version: None,
                remote_version: None,
            }),
            Some(meta) => {
                let in_sync = sync_state
                    .secrets
                    .get(key)
                    .map(|s| s.version == meta.version && s.updated_at == meta.updated_at)
                    .unwrap_or(false);
                entries.push(DiffEntry {
                    key: key.clone(),
                    state: if in_sync {
                        SecretDiffState::InSync
                    } else {
                        SecretDiffState::Modified
                    },
                    local_version: None,
                    remote_version: Some(meta.version),
                });
            }
        }
    }

    // Remote-only keys.
    for meta in remote {
        if !local.contains_key(&meta.key) {
            entries.push(DiffEntry {
                key: meta.key.clone(),
                state: SecretDiffState::OnlyRemote,
                local_version: None,
                remote_version: Some(meta.version),
            });
        }
    }

    entries.sort_by(|a, b| a.key.cmp(&b.key));
    DiffReport { entries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SecretSyncInfo;
    use chrono::TimeZone;

    fn meta(key: &str, version: i32, updated_at: chrono::DateTime<chrono::Utc>) -> SecretMeta {
        SecretMeta {
            id: uuid::Uuid::now_v7(),
            project_id: uuid::Uuid::now_v7(),
            env_id: uuid::Uuid::now_v7(),
            key: key.to_string(),
            version,
            created_by: uuid::Uuid::now_v7(),
            created_at: updated_at,
            updated_at,
            deleted_at: None,
        }
    }

    fn ts(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn diff_three_states() {
        let local = HashMap::from([
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ]);
        let remote = vec![meta("B", 3, ts(100)), meta("C", 1, ts(50))];
        let state = SyncState {
            project_id: None,
            env_id: None,
            secrets: HashMap::new(), // no sync state => B is Modified
        };

        let report = diff_metadata(&local, &remote, &state);
        let by_key: HashMap<&str, SecretDiffState> = report
            .entries
            .iter()
            .map(|e| (e.key.as_str(), e.state.clone()))
            .collect();

        assert_eq!(by_key.get("A"), Some(&SecretDiffState::OnlyLocal));
        assert_eq!(by_key.get("B"), Some(&SecretDiffState::Modified));
        assert_eq!(by_key.get("C"), Some(&SecretDiffState::OnlyRemote));
    }

    #[test]
    fn diff_uses_sync_state_to_detect_in_sync() {
        let local = HashMap::from([("B".to_string(), "2".to_string())]);
        let remote = vec![meta("B", 3, ts(100))];
        let mut state = SyncState::default();
        state.secrets.insert(
            "B".to_string(),
            SecretSyncInfo {
                version: 3,
                updated_at: ts(100),
            },
        );

        let report = diff_metadata(&local, &remote, &state);
        assert_eq!(report.entries[0].state, SecretDiffState::InSync);
    }

    #[test]
    fn diff_sorts_by_key() {
        let local = HashMap::from([("Z".to_string(), "1".to_string())]);
        let remote = vec![meta("A", 1, ts(10))];
        let report = diff_metadata(&local, &remote, &SyncState::default());
        let keys: Vec<&str> = report.entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["A", "Z"]);
    }
}
