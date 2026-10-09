use axum::{extract::{Query, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::models::*;
use pandapass_core::policy::{PolicyDecision, PolicyInput};
use pandapass_core::scanner::RegexScanner;
use pandapass_core::scanner::Scanner;
use pandapass_db as db;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::middleware::auth::{Auth, ApiError};
use crate::state::AppState;

/// A scan run's aggregate summary, stored in the audit meta.
///
/// Deliberately contains no per-finding detail (no secret keys, no rule ids,
/// no offsets) — only counts. Per-finding data lives in `scan_findings`, which
/// is ephemeral and replaced on every scan; the audit log is permanent, so
/// only the summary belongs there.
#[derive(Serialize)]
struct ScanRunSummary {
    secrets_scanned: usize,
    findings: usize,
    projects: usize,
    envs: usize,
    errors: usize,
}

#[derive(Deserialize)]
pub struct ScanResultsQuery {
    pub project_id: Option<uuid::Uuid>,
    pub env_id: Option<uuid::Uuid>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

/// Run a full secret scan: decrypt every active secret, run the built-in
/// scanner, and replace the persisted findings with the new results.
///
/// Admin only — this decrypts every secret in the system, so it is the most
/// privileged read there is. For each secret, the master key of its *creator*
/// is used (secrets are encrypted with the writer's master key). If a creator
/// has no envelope sealed to the server, that secret is skipped and counted as
/// an error rather than failing the whole run.
pub async fn trigger_scan(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    // Policy evaluation (global scope — a scan reaches every project)
    let input = PolicyInput::for_context(&auth, "", "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(None, None, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::SecretScan);
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    // Cache of user_id -> master key, so a user with many secrets is only
    // decrypted once per scan run.
    let mut mk_cache: HashMap<uuid::Uuid, pandapass_core::crypto::MasterKey> = HashMap::new();

    let secrets = db::all_secrets(&state.db).await?;
    let scanner = RegexScanner::builtin();
    let mut records: Vec<ScanFindingRecord> = Vec::new();
    let mut errors = 0usize;
    let mut projects: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
    let mut envs: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();

    for secret in &secrets {
        projects.insert(secret.meta.project_id);
        envs.insert(secret.meta.env_id);

        let mk = match mk_cache.get(&secret.meta.created_by) {
            Some(mk) => mk,
            None => {
                match crate::routes::secrets::get_master_key(&state, secret.meta.created_by).await {
                    Ok(mk) => {
                        mk_cache.insert(secret.meta.created_by, mk);
                        mk_cache.get(&secret.meta.created_by).unwrap()
                    }
                    Err(_) => {
                        // The creator's envelope is missing or not sealed to
                        // this server — skip and count rather than aborting the
                        // whole run. This is the documented M4 tolerance.
                        errors += 1;
                        continue;
                    }
                }
            }
        };

        let value = match secret.value_enc.decrypt(mk) {
            Ok(v) => v,
            Err(_) => {
                // A corrupted or wrong-key secret must not fail the run either.
                errors += 1;
                continue;
            }
        };

        let findings = scanner.scan(&secret.meta.key, value.expose_secret());
        for f in findings {
            records.push(ScanFindingRecord {
                id: uuid::Uuid::now_v7(),
                project_id: secret.meta.project_id,
                env_id: secret.meta.env_id,
                secret_key: f.secret_key,
                rule_id: f.rule_id,
                rule_name: f.rule_name,
                severity: f.severity,
                match_start: f.match_start,
                match_end: f.match_end,
                detected_at: chrono::Utc::now(),
            });
        }
    }

    db::replace_scan_findings(&state.db, &records).await?;

    let summary = ScanRunSummary {
        secrets_scanned: secrets.len(),
        findings: records.len(),
        projects: projects.len(),
        envs: envs.len(),
        errors,
    };

    let mut audit = AuditContext::new(&auth, AuditAction::SecretScan)
        .with_meta(serde_json::to_value(&summary).unwrap_or_default());
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::to_value(&summary).unwrap_or_default()))
}

/// List persisted scan findings, filtered and paginated.
///
/// Admin only. The response contains secret *key names* and rule/offset
/// metadata — never plaintext fragments.
pub async fn list_results(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Query(query): Query<ScanResultsQuery>,
) -> Result<Json<PaginatedResponse<ScanFindingRecord>>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);

    let items = db::list_scan_findings(
        &state.db,
        query.project_id,
        query.env_id,
        page,
        per_page,
    )
    .await?;
    let total = db::count_scan_findings(&state.db, query.project_id, query.env_id).await?;

    Ok(Json(PaginatedResponse::new(items, total, page, per_page)))
}