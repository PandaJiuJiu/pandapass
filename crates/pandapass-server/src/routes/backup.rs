use axum::{extract::State, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::models::*;
use serde::Serialize;

use crate::middleware::auth::{ApiError, Auth};
use crate::state::AppState;

/// A consistent snapshot of the SQLite database, returned as bytes so the CLI
/// can seal it with age before it touches disk.
///
/// The snapshot is created with `VACUUM INTO`, which produces a consistent
/// copy of the live database without stopping writes. The bytes are base64
/// encoded in the JSON envelope; a SHA-256 is included so the CLI can verify
/// integrity after decryption.
#[derive(Serialize)]
pub struct BackupSnapshotResponse {
    pub format: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub db: BackupDb,
}

#[derive(Serialize)]
pub struct BackupDb {
    pub bytes_b64: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Admin: produce a consistent SQLite snapshot for backup.
///
/// The snapshot file lives only long enough to be read and base64-encoded; it
/// is deleted before the response is sent, so no plaintext database copy is
/// left in the temp directory.
pub async fn create_backup(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<BackupSnapshotResponse>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    // Unique file name in the configured backup dir (or the system temp dir).
    let dir = state
        .config
        .backup_dir
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::temp_dir().display().to_string());
    std::fs::create_dir_all(&dir)
        .map_err(|e| ApiError::Internal(format!("backup dir {dir:?}: {e}")))?;
    let path =
        std::path::PathBuf::from(dir).join(format!("pandapass-backup-{}.db", uuid::Uuid::now_v7()));

    // `VACUUM INTO` produces a consistent snapshot of the live database. It
    // must run as a raw SQL statement (sqlx has no helper for it).
    let snapshot = sqlx::query(&format!(
        "VACUUM INTO '{}'",
        path.display().to_string().replace('\'', "''")
    ))
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("VACUUM INTO failed: {e}")))?;

    // Read the snapshot and delete it immediately so a plaintext database
    // copy never lingers on disk.
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| ApiError::Internal(format!("read snapshot: {e}")))?;
    let _ = tokio::fs::remove_file(&path).await;

    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let created_at = chrono::Utc::now();

    let mut audit = AuditContext::new(&auth, AuditAction::BackupCreate);
    audit = audit.with_meta(serde_json::json!({
        "size_bytes": bytes.len(),
        "sha256": sha256,
    }));
    state.audit.log_success(&mut audit).await.ok();

    // `snapshot` is unused but keeps the VACUUM result bound; drop it to
    // silence the unused variable warning if the result is never inspected.
    let _ = snapshot;

    Ok(Json(BackupSnapshotResponse {
        format: "pandapass-sqlite-snapshot-v1".to_string(),
        created_at,
        db: BackupDb {
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            sha256,
            size_bytes: bytes.len() as u64,
        },
    }))
}
