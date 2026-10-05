use anyhow::Result;
use reqwest::{header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue}, Client, Method};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use pandapass_core::models::{
    AuditLog, CreateEnvRequest, CreateProjectRequest, PaginatedResponse, ProjectRole,
    ProjectWithRole, ServiceToken, UpdateMemberRequest,
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

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn set_auth_token(&self, token: Option<String>) {
        *self.auth_token.write().await = token;
    }

    pub async fn auth_token(&self) -> Option<String> {
        self.auth_token.read().await.clone()
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

    pub async fn register(&self, email: &str, password: &str) -> Result<LoginResponse> {
        let req = crate::model::RegisterRequest {
            email: email.to_string(),
            password: password.to_string(),
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

    pub async fn batch_set_secrets(
        &self,
        project_slug: &str,
        env_slug: &str,
        secrets: &std::collections::HashMap<String, String>,
    ) -> Result<serde_json::Value> {
        let req = crate::model::BatchSetRequest {
            secrets: secrets.clone(),
        };
        self.post(
            &format!("/projects/{project_slug}/envs/{env_slug}/secrets/batch"),
            &req,
        )
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

    // ─────────────────────────── MCP internal ───────────────────────────

    /// Fetch a secret's ciphertext for local decryption.
    ///
    /// The server never sends plaintext: it returns the ChaCha20-Poly1305 blob and
    /// the CLI unwraps it with the user's own master key.
    pub async fn mcp_fetch_secret(
        &self,
        project_id: uuid::Uuid,
        env_id: uuid::Uuid,
        key: &str,
    ) -> Result<pandapass_core::models::Secret> {
        let req = crate::model::McpGetSecretRequest {
            key: key.to_string(),
            project_id: Some(project_id),
            env_id: Some(env_id),
        };
        self.post("/internal/secret", &req).await
    }

    pub async fn mcp_list_secrets(
        &self,
        project_id: uuid::Uuid,
        env_id: uuid::Uuid,
    ) -> Result<Vec<pandapass_core::models::SecretMeta>> {
        let req = crate::model::McpListSecretsRequest {
            project_id: Some(project_id),
            env_id: Some(env_id),
        };
        self.post("/internal/secrets", &req).await
    }

    /// Ask the server to run a command with secrets injected into its environment.
    ///
    /// This is the path that keeps secrets out of the agent's context entirely.
    pub async fn mcp_exec(
        &self,
        project_id: uuid::Uuid,
        env_id: uuid::Uuid,
        keys: &[String],
        command: &[String],
        timeout_secs: u64,
    ) -> Result<pandapass_core::models::CommandResult> {
        let req = crate::model::McpExecRequest {
            keys: keys.to_vec(),
            command: command.to_vec(),
            project_id: Some(project_id),
            env_id: Some(env_id),
            timeout_secs,
        };
        self.post("/internal/exec", &req).await
    }
}