//! Policy evaluation engine (M3)
//!
//! Uses `regorus` (pure Rust Rego interpreter) so the distroless image
//! needs no Go binary. Policies are stored in the `policies` table with
//! `rego_source` and `enabled` flag. Bindings in `policy_bindings` attach
//! a policy to a (project_id?, env_id?) scope. Resolution order:
//! env-level > project-level > global.
//!
//! Input shape for every decision:
//! ```json
//! {
//!   "action": "read_secret",        // or write_secret, list_secrets, delete_secret, read_audit, ...
//!   "role": "editor",               // "owner" | "editor" | "viewer" | "admin" (global)
//!   "env": "prod",                  // environment slug
//!   "project": "my-app",            // project slug
//!   "secret_key": "DB_URL"          // optional, for secret-specific decisions
//! }
//! ```
//!
//! Policy must define `deny[msg]` rules. If any deny fires, access is denied
//! with the first message. If no policy applies or none denies, allow.

use crate::models::{Permission, Policy, PolicyBinding};
use regorus::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Policy evaluation error
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Policy engine error: {0}")]
    Engine(String),
    #[error("No policy engine initialized")]
    NotInitialized,
    #[error("Policy compile failed: {0}")]
    Compile(String),
}

/// Result of a policy check
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow,
    Deny { policy_id: Uuid, message: String },
}

/// Compiled policy bundle (one per policy, cached)
#[derive(Debug, Clone)]
struct CompiledPolicy {
    id: Uuid,
    engine: Engine,
}

/// Policy evaluation service
#[derive(Clone)]
pub struct PolicyEngine {
    /// Compiled policies, keyed by policy id
    policies: Arc<RwLock<HashMap<Uuid, CompiledPolicy>>>,
    /// Active bindings, keyed by (project_id, env_id) -> list of policy_ids
    /// None keys mean "global"
    bindings: Arc<RwLock<HashMap<(Option<Uuid>, Option<Uuid>), Vec<Uuid>>>>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            bindings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add or update a policy (recompiles the Rego source)
    pub async fn upsert_policy(&self, policy: &Policy) -> Result<(), PolicyError> {
        if !policy.enabled {
            self.policies.write().await.remove(&policy.id);
            return Ok(());
        }

        let mut engine = Engine::new();
        // regorus defaults to Rego v1; our examples use v0-style `package pandapass.authz`.
        engine.set_rego_v0(true);

        let path = format!("policy://{}.rego", policy.id);
        engine
            .add_policy(path, policy.rego_source.clone())
            .map_err(|e| PolicyError::Compile(e.to_string()))?;

        let compiled = CompiledPolicy {
            id: policy.id,
            engine,
        };

        self.policies.write().await.insert(policy.id, compiled);
        Ok(())
    }

    /// Remove a policy
    pub async fn remove_policy(&self, id: Uuid) {
        self.policies.write().await.remove(&id);
    }

    /// Rebuild the binding index from the full list
    pub async fn rebuild_bindings(&self, bindings: &[PolicyBinding]) {
        let mut map: HashMap<(Option<Uuid>, Option<Uuid>), Vec<Uuid>> = HashMap::new();
        for b in bindings {
            let key = (b.project_id, b.env_id);
            map.entry(key).or_default().push(b.policy_id);
        }
        *self.bindings.write().await = map;
    }

    /// Evaluate all policies applicable to the given context.
    /// Returns the first deny, or Allow if none deny.
    ///
    /// A binding may name a project, an environment, both, or neither. All four
    /// shapes are reachable from the API, so all four are looked up, most
    /// specific first: a rule written for one environment should be able to
    /// override the shape of a broader one.
    pub async fn evaluate(
        &self,
        project_id: Option<Uuid>,
        env_id: Option<Uuid>,
        input: &PolicyInput,
    ) -> Result<PolicyDecision, PolicyError> {
        let bindings = self.bindings.read().await;
        let policies = self.policies.read().await;

        let candidate_keys = [
            (project_id, env_id), // project + env
            (None, env_id),       // env only, across projects
            (project_id, None),   // project-wide
            (None, None),         // global
        ];

        let mut seen: Vec<Uuid> = Vec::new();
        for key in candidate_keys {
            let Some(policy_ids) = bindings.get(&key) else {
                continue;
            };
            for pid in policy_ids {
                // A policy bound at two levels of the same request must not be
                // evaluated twice: the second evaluation reports a duplicate
                // deny that looks like a second, independent refusal.
                if seen.contains(pid) {
                    continue;
                }
                seen.push(*pid);

                if let Some(compiled) = policies.get(pid) {
                    let decision = Self::eval_single(compiled, input)?;
                    if let PolicyDecision::Deny { message, .. } = decision {
                        return Ok(PolicyDecision::Deny {
                            policy_id: *pid,
                            message,
                        });
                    }
                }
            }
        }

        Ok(PolicyDecision::Allow)
    }

    fn eval_single(
        compiled: &CompiledPolicy,
        input: &PolicyInput,
    ) -> Result<PolicyDecision, PolicyError> {
        let mut engine = compiled.engine.clone();

        let input_json =
            serde_json::to_string(input).map_err(|e| PolicyError::Engine(e.to_string()))?;
        engine
            .set_input_json(&input_json)
            .map_err(|e| PolicyError::Engine(e.to_string()))?;

        // Query the deny rule. The policy must expose `data.pandapass.authz.deny`.
        let value = engine
            .eval_rule("data.pandapass.authz.deny".to_string())
            .map_err(|e| PolicyError::Engine(e.to_string()))?;

        if let Ok(set) = value.as_set() {
            for msg_val in set.iter() {
                if let Ok(msg) = msg_val.as_string() {
                    return Ok(PolicyDecision::Deny {
                        policy_id: compiled.id,
                        message: msg.to_string(),
                    });
                }
            }
        }

        Ok(PolicyDecision::Allow)
    }
}

/// Input passed to every policy evaluation
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyInput {
    pub action: String, // "read_secret", "write_secret", "list_secrets", "delete_secret", "read_audit"
    pub role: String,   // "owner" | "editor" | "viewer" | "admin", or "none"
    pub token: bool,    // true when the caller is a service token, not a human
    pub env: String,    // environment slug
    pub project: String, // project slug
    pub secret_key: Option<String>,
}

impl PolicyInput {
    /// Build the evaluation input for a request.
    ///
    /// A service token is deliberately *not* reported as its creator's role.
    /// Tokens are usually minted by admins, so inheriting that role would make
    /// every `input.role != "admin"` rule a no-op — the same class of bug as
    /// the one that made token scopes decorative before.
    pub fn for_context(
        ctx: &crate::models::AuthContext,
        project_slug: &str,
        env_slug: &str,
        perm: Permission,
        secret_key: Option<&str>,
    ) -> Self {
        let action = match perm {
            Permission::ReadSecret => "read_secret",
            Permission::WriteSecret | Permission::DeleteSecret => "write_secret",
            Permission::ListSecrets => "list_secrets",
            Permission::ReadAudit => "read_audit",
            Permission::RunSecret => "run_secret",
            Permission::CreateProject
            | Permission::ReadProject
            | Permission::UpdateProject
            | Permission::DeleteProject => "manage_project",
            Permission::ManageMembers => "manage_members",
            Permission::CreateEnv | Permission::UpdateEnv | Permission::DeleteEnv => "manage_env",
            Permission::CreateToken => "create_token",
            Permission::RevokeToken => "revoke_token",
            Permission::ManageUsers => "manage_users",
        };

        let is_service_token = ctx.service_token.is_some();
        let role = if is_service_token {
            ctx.project_role
                .map(|r| r.as_str().to_string())
                .unwrap_or_else(|| "none".to_string())
        } else if ctx.user.global_role == crate::models::GlobalRole::Admin {
            "admin".to_string()
        } else {
            ctx.project_role
                .map(|r| r.as_str().to_string())
                .unwrap_or_else(|| "none".to_string())
        };

        Self {
            action: action.to_string(),
            role,
            token: is_service_token,
            env: env_slug.to_string(),
            project: project_slug.to_string(),
            secret_key: secret_key.map(|s| s.to_string()),
        }
    }
}
