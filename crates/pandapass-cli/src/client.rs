use anyhow::Result;
use reqwest::{header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue}, Client, Method};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use pandapass_core::models::{
    AuditLog, CaKey, CaKeyType, CreateEnvRequest, CreateProjectRequest, DynamicCred, DynamicCredKind, PaginatedResponse, Policy, PolicyBinding,
    ProjectRole, ProjectWithRole, SshCert, SshKeyType, ServiceToken, UpdateMemberRequest,
};

use crate::model::{
    AddMemberRequest, CreateTokenRequest, CreateTokenResponse, LoginResponse, ProjectMemberDetail, SecretValueResponse,
};

/// CLI configuration stored in ~/.pandapass/config.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    /// Session token from `pandapass login`, or a service token from `token create`.
    pub auth_token: Option<String>,
    pub default_project: Option<String>,
    pub default_env: Option<String>,
    /// Path to the age identity file holding this user's master-key unwrap key.
    pub age_identity_file: Option<PathBuf>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8233".to_string(),
            auth_token: None,
            default_project: None,
            default_env: None,
            age_identity_file: None,
        }
    }
}

/// HTTP client for the PandaPass API.
///
/// The CLI never talks to the database directly — every operation goes through
/// the API so that all access lands in the audit log.
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    auth_token: Arc<RwLock<Option<String>>>,
    /// This user's age identity, used to unwrap their master key locally so
    /// secret values never have to be decrypted by the server on our behalf.
    age_identity: Arc<RwLock<Option<age::x25519::Identity>>>,
}

impl ApiClient {
    pub fn new(base_url: String, insecure: bool) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(insecure)
            .build()?;

        Ok(Self {
            client,
            base_url,
            auth_token: Arc::new(RwLock::new(None)),
            age_identity: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn set_auth_token(&self, token: Option<String>) {
        *self.auth_token.write().await = token;
    }

    pub async fn set_age_identity(&self, identity: Option<age::x25519::Identity>) {
        *self.age_identity.write().await = identity;
    }

    async fn request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
    ) -> Result<R> {
        let url = format!("{}/api/v1{}", self.base_url.trim_end_matches('/'), path);
        let token = self.auth_token.read().await.clone();

        let mut req = self.client
            .request(method, &url)
            .header(CONTENT_TYPE, "application/json");

        if let Some(t) = token {
            req = req.header(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {t}"))?);
        }
        if let Some(b) = body {
            req = req.json(b);
        }

        let resp = req.send().await?;
        let status = resp.status();

        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            // Server errors carry `{"error":{"code","message"}}`; surface the message only.
            let detail = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
                .unwrap_or(text);
            anyhow::bail!("{status}: {detail}");
        }

        Ok(resp.json().await?)
    }

    pub async fn get<R: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<R> {
        self.request(Method::GET, path, None::<&()>).await
    }

    pub async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        self.request(Method::POST, path, Some(body)).await
    }

    pub async fn patch<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        self.request(Method::PATCH, path, Some(body)).await
    }

    pub async fn delete<R: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<R> {
        self.request(Method::DELETE, path, None::<&()>).await
    }

    // ─────────────────────────── auth ───────────────────────────

    pub async fn register(
        &self,
        email: &str,
        password: &str,
        age_public_key: Option<&str>,
    ) -> Result<LoginResponse> {
        let req = crate::model::RegisterRequest {
            email: email.to_string(),
            password: password.to_string(),
            age_public_key: age_public_key.map(|s| s.to_string()),
        };
        self.post("/auth/register", &req).await
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<LoginResponse> {
        let req = pandapass_core::models::LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
            totp_code: totp_code.map(String::from),
        };
        self.post("/auth/login", &req).await
    }

    pub async fn logout(&self) -> Result<()> {
        let _: serde_json::Value = self.post("/auth/logout", &()).await?;
        self.set_auth_token(None).await;
        Ok(())
    }

    pub async fn me(&self) -> Result<pandapass_core::models::UserPublic> {
        self.get("/auth/me").await
    }

    // ─────────────────────────── projects & envs ───────────────────────────

    pub async fn list_projects(&self) -> Result<Vec<ProjectWithRole>> {
        self.get("/projects").await
    }

    pub async fn create_project(&self, req: &CreateProjectRequest) -> Result<ProjectWithRole> {
        self.post("/projects", req).await
    }

    pub async fn get_project(&self, slug: &str) -> Result<ProjectWithRole> {
        self.get(&format!("/projects/{slug}")).await
    }

    pub async fn update_project(
        &self,
        slug: &str,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<ProjectWithRole> {
        let req = pandapass_core::models::UpdateProjectRequest { name, description };
        self.patch(&format!("/projects/{slug}"), &req).await
    }

    pub async fn delete_project(&self, slug: &str) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/projects/{slug}")).await?;
        Ok(())
    }

    pub async fn delete_env(&self, project_slug: &str, env_slug: &str) -> Result<()> {
        let _: serde_json::Value = self
            .delete(&format!("/projects/{project_slug}/envs/{env_slug}"))
            .await?;
        Ok(())
    }

    /// Resolve a project slug to its id. The audit and token endpoints take a
    /// UUID while every other CLI command speaks slugs, so the conversion is
    /// done here rather than making the user look up an id by hand.
    pub async fn resolve_project_id(&self, slug: &str) -> Result<uuid::Uuid> {
        Ok(self.get_project(slug).await?.project.id)
    }

    pub async fn list_envs(&self, project_slug: &str) -> Result<Vec<pandapass_core::models::Environment>> {
        self.get(&format!("/projects/{project_slug}/envs")).await
    }

    pub async fn create_env(
        &self,
        project_slug: &str,
        req: &CreateEnvRequest,
    ) -> Result<pandapass_core::models::Environment> {
        self.post(&format!("/projects/{project_slug}/envs"), req)
            .await
    }

    // ─────────────────────────── secrets ────────────���──────────────

    pub async fn list_secrets(
        &self,
        project_slug: &str,
        env_slug: &str,
    ) -> Result<PaginatedResponse<pandapass_core::models::SecretMeta>> {
        self.get(&format!("/projects/{project_slug}/envs/{env_slug}/secrets"))
            .await
    }

    pub async fn get_secret(
        &self,
        project_slug: &str,
        env_slug: &str,
        key: &str,
    ) -> Result<SecretValueResponse> {
        self.get(&format!(
            "/projects/{project_slug}/envs/{env_slug}/secrets/{key}"
        ))
        .await
    }

    pub async fn set_secret(
        &self,
        project_slug: &str,
        env_slug: &str,
        key: &str,
        value: &str,
    ) -> Result<SecretValueResponse> {
        let req = pandapass_core::models::SetSecretRequest {
            key: key.to_string(),
            value: value.to_string(),
        };
        self.post(&format!("/projects/{project_slug}/envs/{env_slug}/secrets"), &req)
            .await
    }

    pub async fn delete_secret(
        &self,
        project_slug: &str,
        env_slug: &str,
        key: &str,
    ) -> Result<()> {
        let _: serde_json::Value = self
            .delete(&format!(
                "/projects/{project_slug}/envs/{env_slug}/secrets/{key}"
            ))
            .await?;
        Ok(())
    }

    // ─────────────────────────── members ───────────────────────────

    pub async fn list_members(
        &self,
        project_slug: &str,
    ) -> Result<Vec<ProjectMemberDetail>> {
        self.get(&format!("/projects/{project_slug}/members")).await
    }

    pub async fn add_member(
        &self,
        project_slug: &str,
        email: &str,
        role: ProjectRole,
    ) -> Result<ProjectMemberDetail> {
        let req = AddMemberRequest {
            email: email.to_string(),
            role,
        };
        self.post(&format!("/projects/{project_slug}/members"), &req)
            .await
    }

    pub async fn update_member(
        &self,
        project_slug: &str,
        user_id: uuid::Uuid,
        role: ProjectRole,
    ) -> Result<serde_json::Value> {
        let req = UpdateMemberRequest { role };
        self.patch(
            &format!("/projects/{project_slug}/members/{user_id}"),
            &req,
        )
        .await
    }

    pub async fn remove_member(
        &self,
        project_slug: &str,
        user_id: uuid::Uuid,
    ) -> Result<()> {
        let _: serde_json::Value = self
            .delete(&format!("/projects/{project_slug}/members/{user_id}"))
            .await?;
        Ok(())
    }

    // ─────────────────────────── tokens ───────────────────────────

    pub async fn list_tokens(&self) -> Result<Vec<ServiceToken>> {
        self.get("/tokens").await
    }

    pub async fn create_token(&self, req: &CreateTokenRequest) -> Result<CreateTokenResponse> {
        self.post("/tokens", req).await
    }

    pub async fn revoke_token(&self, id: uuid::Uuid) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/tokens/{id}")).await?;
        Ok(())
    }

    // ─────────────────────────── audit ───────────────────────────

    pub async fn list_audit(
        &self,
        project_id: Option<uuid::Uuid>,
        page: i64,
        per_page: i64,
    ) -> Result<PaginatedResponse<AuditLog>> {
        let mut path = format!("/audit?page={page}&per_page={per_page}");
        if let Some(id) = project_id {
            path.push_str(&format!("&project_id={id}"));
        }
        self.get(&path).await
    }

    /// Verify the audit log HMAC chain (admin only).
    pub async fn verify_audit(&self) -> Result<serde_json::Value> {
        self.get("/audit/verify").await
    }

    // ─────────────────────────── dynamic credentials (M2) ───────────────────────────

    pub async fn list_dynamic_creds(
        &self,
        project_slug: &str,
        env_slug: &str,
    ) -> Result<Vec<DynamicCred>> {
        self.get(&format!("/projects/{project_slug}/envs/{env_slug}/creds")).await
    }

    pub async fn create_dynamic_cred(
        &self,
        project_slug: &str,
        env_slug: &str,
        kind: DynamicCredKind,
        username: &str,
        ttl_seconds: i64,
    ) -> Result<serde_json::Value> {
        let req = serde_json::json!({
            "kind": kind.as_str(),
            "username": username,
            "ttl_seconds": ttl_seconds,
        });
        self.post(&format!("/projects/{project_slug}/envs/{env_slug}/creds"), &req).await
    }

    pub async fn revoke_dynamic_cred(
        &self,
        project_slug: &str,
        env_slug: &str,
        id: uuid::Uuid,
    ) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/projects/{project_slug}/envs/{env_slug}/creds/{id}")).await?;
        Ok(())
    }

    // ─────────────────────────── policies (M3) ───────────────────────────

    pub async fn list_policies(&self, enabled_only: bool) -> Result<Vec<Policy>> {
        let path = format!("/policies?enabled_only={enabled_only}");
        self.get(&path).await
    }

    pub async fn create_policy(&self, name: &str, rego_source: &str) -> Result<Policy> {
        let req = serde_json::json!({ "name": name, "rego_source": rego_source });
        self.post("/policies", &req).await
    }

    pub async fn get_policy(&self, id: uuid::Uuid) -> Result<Policy> {
        self.get(&format!("/policies/{id}")).await
    }

    pub async fn update_policy(
        &self,
        id: uuid::Uuid,
        name: Option<&str>,
        rego_source: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<()> {
        let req = serde_json::json!({
            "name": name,
            "rego_source": rego_source,
            "enabled": enabled,
        });
        let _: serde_json::Value = self.patch(&format!("/policies/{id}"), &req).await?;
        Ok(())
    }

    pub async fn delete_policy(&self, id: uuid::Uuid) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/policies/{id}")).await?;
        Ok(())
    }

    pub async fn list_policy_bindings(
        &self,
        project_id: Option<uuid::Uuid>,
        env_id: Option<uuid::Uuid>,
    ) -> Result<Vec<PolicyBinding>> {
        let mut path = "/policies/bindings".to_string();
        let mut params = Vec::new();
        if let Some(id) = project_id {
            params.push(format!("project_id={id}"));
        }
        if let Some(id) = env_id {
            params.push(format!("env_id={id}"));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.get(&path).await
    }

    pub async fn bind_policy(
        &self,
        policy_id: uuid::Uuid,
        project_id: Option<uuid::Uuid>,
        env_id: Option<uuid::Uuid>,
    ) -> Result<PolicyBinding> {
        let req = serde_json::json!({
            "policy_id": policy_id,
            "project_id": project_id,
            "env_id": env_id,
        });
        self.post("/policies/bindings", &req).await
    }

    pub async fn unbind_policy(&self, id: uuid::Uuid) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/policies/bindings/{id}")).await?;
        Ok(())
    }

    // ─────────────────────────── PKI/CA (M4) ───────────────────────────

    pub async fn list_ca_keys(&self, include_revoked: bool) -> Result<Vec<CaKey>> {
        let path = format!("/ca?include_revoked={include_revoked}");
        self.get(&path).await
    }

    pub async fn create_ca_key(
        &self,
        kind: CaKeyType,
        key_pem: &str,
        cert_pem: &str,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<CaKey> {
        let req = serde_json::json!({
            "kind": kind.as_str(),
            "key_pem": key_pem,
            "cert_pem": cert_pem,
            "not_before": not_before.to_rfc3339(),
            "not_after": not_after.to_rfc3339(),
        });
        self.post("/ca", &req).await
    }

    pub async fn get_ca_key(&self, id: uuid::Uuid) -> Result<CaKey> {
        self.get(&format!("/ca/{id}")).await
    }

    pub async fn revoke_ca_key(&self, id: uuid::Uuid) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/ca/{id}")).await?;
        Ok(())
    }

    /// Sign an SSH user certificate with a stored CA. The user's public key
    /// travels; their private key never does.
    pub async fn sign_ssh_cert(
        &self,
        ca_id: uuid::Uuid,
        user_id: uuid::Uuid,
        project_id: Option<uuid::Uuid>,
        principal: &str,
        user_public_key_openssh: &str,
        key_type: SshKeyType,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<serde_json::Value> {
        let req = serde_json::json!({
            "user_id": user_id,
            "project_id": project_id,
            "principal": principal,
            "user_public_key_openssh": user_public_key_openssh,
            "key_type": key_type.as_str(),
            "not_before": not_before.to_rfc3339(),
            "not_after": not_after.to_rfc3339(),
        });
        self.post(&format!("/ca/{ca_id}/sign-ssh"), &req).await
    }

    // ─────────────────────────── SSH certificates (M4) ───────────────────────────

    pub async fn list_ssh_certs(
        &self,
        user_id: Option<uuid::Uuid>,
        project_id: Option<uuid::Uuid>,
        include_revoked: bool,
    ) -> Result<Vec<SshCert>> {
        let mut path = "/ssh-certs".to_string();
        let mut params = Vec::new();
        if let Some(id) = user_id {
            params.push(format!("user_id={id}"));
        }
        if let Some(id) = project_id {
            params.push(format!("project_id={id}"));
        }
        params.push(format!("include_revoked={include_revoked}"));
        path.push('?');
        path.push_str(&params.join("&"));
        self.get(&path).await
    }

    pub async fn create_ssh_cert(
        &self,
        user_id: uuid::Uuid,
        project_id: Option<uuid::Uuid>,
        principal: &str,
        cert_pem: &str,
        key_type: SshKeyType,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<SshCert> {
        let req = serde_json::json!({
            "user_id": user_id,
            "project_id": project_id,
            "principal": principal,
            "cert_pem": cert_pem,
            "key_type": key_type.as_str(),
            "valid_before": not_before.to_rfc3339(),
            "valid_after": not_after.to_rfc3339(),
        });
        self.post("/ssh-certs", &req).await
    }

    pub async fn revoke_ssh_cert(&self, id: uuid::Uuid) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/ssh-certs/{id}")).await?;
        Ok(())
    }
}
