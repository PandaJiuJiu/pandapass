use pandapass_core::{
    crypto::{EncryptedSecret, Envelope},
    error::Result,
    models::*,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::str::FromStr;
use std::time::Duration;

pub type Db = SqlitePool;
pub type Tx<'a> = Transaction<'a, Sqlite>;

/// Connect to SQLite with proper pragmas for a secrets vault
pub async fn connect(url: &str) -> Result<Db> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(opts)
        .await?;

    Ok(pool)
}

/// Run all pending migrations
pub async fn migrate(pool: &Db) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

// ─────────────────────────── helpers ───────────────────────────

fn parse_ts(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

fn ts(v: chrono::DateTime<chrono::Utc>) -> String {
    v.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn opt_ts(v: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    v.map(ts)
}

fn parse_opt_ts(s: Option<String>) -> Option<chrono::DateTime<chrono::Utc>> {
    s.map(|s| parse_ts(&s))
}

fn enc_json(e: &EncryptedSecret) -> String {
    serde_json::to_string(e).unwrap_or_default()
}

fn dec_json(s: &str) -> EncryptedSecret {
    serde_json::from_str(s).unwrap_or(EncryptedSecret {
        nonce: String::new(),
        ciphertext: String::new(),
    })
}

// ─────────────────────────── users ───────────────────────────

pub async fn create_user(
    db: &Db,
    email: &str,
    password_hash: &str,
    global_role: GlobalRole,
) -> Result<User> {
    let id = uuid::Uuid::now_v7();
    let now = utc_now();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, totp_secret_enc, totp_enabled,
         recovery_codes_hash, global_role, created_at)
         VALUES (?1, ?2, ?3, NULL, 0, '[]', ?4, ?5)",
    )
    .bind(id.to_string())
    .bind(email)
    .bind(password_hash)
    .bind(global_role_str(global_role))
    .bind(&now)
    .execute(db)
    .await?;

    get_user_by_id(db, id).await
}

fn utc_now() -> String {
    ts(chrono::Utc::now())
}

pub fn global_role_str(r: GlobalRole) -> &'static str {
    match r {
        GlobalRole::Admin => "admin",
        GlobalRole::User => "user",
    }
}

pub fn parse_global_role(s: &str) -> GlobalRole {
    match s {
        "admin" => GlobalRole::Admin,
        _ => GlobalRole::User,
    }
}

pub fn project_role_str(r: ProjectRole) -> &'static str {
    match r {
        ProjectRole::Owner => "owner",
        ProjectRole::Editor => "editor",
        ProjectRole::Viewer => "viewer",
    }
}

pub fn parse_project_role(s: &str) -> ProjectRole {
    match s {
        "owner" => ProjectRole::Owner,
        "editor" => ProjectRole::Editor,
        _ => ProjectRole::Viewer,
    }
}

pub async fn get_user_by_id(db: &Db, id: uuid::Uuid) -> Result<User> {
    let row = sqlx::query("SELECT * FROM users WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("user not found".into()))?;
    Ok(row_to_user(&row))
}

pub async fn get_user_by_email(db: &Db, email: &str) -> Result<Option<User>> {
    let row = sqlx::query("SELECT * FROM users WHERE email = ?1")
        .bind(email)
        .fetch_optional(db)
        .await?;
    Ok(row.as_ref().map(row_to_user))
}

fn row_to_user(row: &SqliteRow) -> User {
    User {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        email: row.get("email"),
        password_hash: row.get("password_hash"),
        totp_secret_enc: row
            .get::<Option<String>, _>("totp_secret_enc")
            .filter(|s| !s.is_empty())
            .map(|s| dec_json(&s)),
        totp_enabled: row.get::<i64, _>("totp_enabled") != 0,
        recovery_codes_hash: row
            .get::<String, _>("recovery_codes_hash")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        global_role: parse_global_role(&row.get::<String, _>("global_role")),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
        disabled_at: parse_opt_ts(row.get("disabled_at")),
        last_login_at: parse_opt_ts(row.get("last_login_at")),
    }
}

pub async fn set_user_totp(
    db: &Db,
    user_id: uuid::Uuid,
    secret_enc: Option<&EncryptedSecret>,
    enabled: bool,
) -> Result<()> {
    let enc = secret_enc.map(enc_json);
    sqlx::query("UPDATE users SET totp_secret_enc = ?2, totp_enabled = ?3 WHERE id = ?1")
        .bind(user_id.to_string())
        .bind(enc)
        .bind(if enabled { 1 } else { 0 })
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_recovery_codes(db: &Db, user_id: uuid::Uuid, hashes: &[String]) -> Result<()> {
    sqlx::query("UPDATE users SET recovery_codes_hash = ?2 WHERE id = ?1")
        .bind(user_id.to_string())
        .bind(hashes.join(","))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn touch_last_login(db: &Db, user_id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET last_login_at = ?2 WHERE id = ?1")
        .bind(user_id.to_string())
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn count_users(db: &Db) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) as c FROM users")
        .fetch_one(db)
        .await?;
    Ok(row.get::<i64, _>("c"))
}

pub async fn set_user_role(db: &Db, user_id: uuid::Uuid, role: GlobalRole) -> Result<()> {
    sqlx::query("UPDATE users SET global_role = ?2 WHERE id = ?1")
        .bind(user_id.to_string())
        .bind(global_role_str(role))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn disable_user(db: &Db, user_id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET disabled_at = ?2 WHERE id = ?1")
        .bind(user_id.to_string())
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn enable_user(db: &Db, user_id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = ?1")
        .bind(user_id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_users(db: &Db) -> Result<Vec<User>> {
    let rows = sqlx::query("SELECT * FROM users ORDER BY created_at")
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(row_to_user).collect())
}

// ─────────────────────────── projects ───────────────────────────

pub async fn create_project(
    db: &Db,
    name: &str,
    slug: &str,
    description: Option<&str>,
    created_by: uuid::Uuid,
) -> Result<Project> {
    let id = uuid::Uuid::now_v7();
    let now = utc_now();
    sqlx::query(
        "INSERT INTO projects (id, name, slug, description, created_by, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(slug)
    .bind(description)
    .bind(created_by.to_string())
    .bind(&now)
    .execute(db)
    .await?;
    get_project(db, id).await
}

pub async fn get_project(db: &Db, id: uuid::Uuid) -> Result<Project> {
    let row = sqlx::query("SELECT * FROM projects WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("project not found".into()))?;
    Ok(row_to_project(&row))
}

pub async fn get_project_by_slug(db: &Db, slug: &str) -> Result<Project> {
    let row = sqlx::query("SELECT * FROM projects WHERE slug = ?1")
        .bind(slug)
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("project not found".into()))?;
    Ok(row_to_project(&row))
}

fn row_to_project(row: &SqliteRow) -> Project {
    Project {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        name: row.get("name"),
        slug: row.get("slug"),
        description: row.get("description"),
        created_by: uuid::Uuid::parse_str(
            row.get::<String, _>("created_by").as_str(),
        )
        .unwrap_or(uuid::Uuid::nil()),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
        updated_at: parse_ts(&row.get::<String, _>("updated_at")),
    }
}

pub async fn update_project(
    db: &Db,
    id: uuid::Uuid,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<()> {
    sqlx::query("UPDATE projects SET name = COALESCE(?2, name), description = COALESCE(?3, description), updated_at = ?4 WHERE id = ?1")
        .bind(id.to_string())
        .bind(name)
        .bind(description)
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_project(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM projects WHERE id = ?1")
        .bind(id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

/// Projects the user is a member of (or all, if admin)
pub async fn list_projects_for_user(
    db: &Db,
    user_id: uuid::Uuid,
    is_admin: bool,
) -> Result<Vec<ProjectWithRole>> {
    let rows = if is_admin {
        sqlx::query(
            "SELECT p.*, pm.role as user_role FROM projects p
             LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = ?1
             ORDER BY p.created_at DESC",
        )
        .bind(user_id.to_string())
        .fetch_all(db)
        .await?
    } else {
        sqlx::query(
            "SELECT p.*, pm.role as user_role FROM projects p
             JOIN project_members pm ON pm.project_id = p.id
             WHERE pm.user_id = ?1
             ORDER BY p.created_at DESC",
        )
        .bind(user_id.to_string())
        .fetch_all(db)
        .await?
    };

    Ok(rows
        .iter()
        .map(|r| ProjectWithRole {
            project: row_to_project(r),
            user_role: r
                .get::<Option<String>, _>("user_role")
                .map(|s| parse_project_role(&s)),
        })
        .collect())
}

// ─────────────────────────── members ───────────────────────────

pub async fn add_member(
    db: &Db,
    project_id: uuid::Uuid,
    user_id: uuid::Uuid,
    role: ProjectRole,
    added_by: uuid::Uuid,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO project_members (project_id, user_id, role, added_by, added_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(project_id.to_string())
    .bind(user_id.to_string())
    .bind(project_role_str(role))
    .bind(added_by.to_string())
    .bind(utc_now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn update_member_role(
    db: &Db,
    project_id: uuid::Uuid,
    user_id: uuid::Uuid,
    role: ProjectRole,
) -> Result<()> {
    sqlx::query("UPDATE project_members SET role = ?3 WHERE project_id = ?1 AND user_id = ?2")
        .bind(project_id.to_string())
        .bind(user_id.to_string())
        .bind(project_role_str(role))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn remove_member(db: &Db, project_id: uuid::Uuid, user_id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM project_members WHERE project_id = ?1 AND user_id = ?2")
        .bind(project_id.to_string())
        .bind(user_id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn get_member_role(
    db: &Db,
    project_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> Result<Option<ProjectRole>> {
    let row = sqlx::query("SELECT role FROM project_members WHERE project_id = ?1 AND user_id = ?2")
        .bind(project_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| parse_project_role(&r.get::<String, _>("role"))))
}

pub async fn list_members(db: &Db, project_id: uuid::Uuid) -> Result<Vec<ProjectMemberDetail>> {
    let rows = sqlx::query(
        "SELECT pm.*, u.email, u.global_role, u.totp_enabled, u.created_at as user_created_at,
                u.last_login_at, u.disabled_at
         FROM project_members pm
         JOIN users u ON u.id = pm.user_id
         WHERE pm.project_id = ?1
         ORDER BY pm.added_at",
    )
    .bind(project_id.to_string())
    .fetch_all(db)
    .await?;

    Ok(rows
        .iter()
        .map(|r| ProjectMemberDetail {
            member: ProjectMember {
                project_id: uuid::Uuid::parse_str(r.get::<String, _>("project_id").as_str())
                    .unwrap_or(uuid::Uuid::nil()),
                user_id: uuid::Uuid::parse_str(r.get::<String, _>("user_id").as_str())
                    .unwrap_or(uuid::Uuid::nil()),
                role: parse_project_role(&r.get::<String, _>("role")),
                added_by: uuid::Uuid::parse_str(r.get::<String, _>("added_by").as_str())
                    .unwrap_or(uuid::Uuid::nil()),
                added_at: parse_ts(&r.get::<String, _>("added_at")),
            },
            user: UserPublic {
                id: uuid::Uuid::parse_str(r.get::<String, _>("user_id").as_str())
                    .unwrap_or(uuid::Uuid::nil()),
                email: r.get("email"),
                global_role: parse_global_role(&r.get::<String, _>("global_role")),
                totp_enabled: r.get::<i64, _>("totp_enabled") != 0,
                created_at: parse_ts(&r.get::<String, _>("user_created_at")),
                last_login_at: parse_opt_ts(r.get("last_login_at")),
            },
        })
        .collect())
}

// ─────────────────────────── environments ───────────────────────────

pub async fn create_env(
    db: &Db,
    project_id: uuid::Uuid,
    name: &str,
    slug: &str,
    description: Option<&str>,
) -> Result<Environment> {
    let id = uuid::Uuid::now_v7();
    let now = utc_now();
    sqlx::query(
        "INSERT INTO environments (id, project_id, name, slug, description, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
    )
    .bind(id.to_string())
    .bind(project_id.to_string())
    .bind(name)
    .bind(slug)
    .bind(description)
    .bind(&now)
    .execute(db)
    .await?;
    get_env(db, id).await
}

pub async fn get_env(db: &Db, id: uuid::Uuid) -> Result<Environment> {
    let row = sqlx::query("SELECT * FROM environments WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("environment not found".into()))?;
    Ok(row_to_env(&row))
}

pub async fn get_env_by_slug(db: &Db, project_id: uuid::Uuid, slug: &str) -> Result<Environment> {
    let row = sqlx::query("SELECT * FROM environments WHERE project_id = ?1 AND slug = ?2")
        .bind(project_id.to_string())
        .bind(slug)
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("environment not found".into()))?;
    Ok(row_to_env(&row))
}

fn row_to_env(row: &SqliteRow) -> Environment {
    Environment {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        project_id: uuid::Uuid::parse_str(row.get::<String, _>("project_id").as_str())
            .unwrap_or(uuid::Uuid::nil()),
        name: row.get("name"),
        slug: row.get("slug"),
        description: row.get("description"),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
        updated_at: parse_ts(&row.get::<String, _>("updated_at")),
    }
}

pub async fn list_envs(db: &Db, project_id: uuid::Uuid) -> Result<Vec<Environment>> {
    let rows = sqlx::query("SELECT * FROM environments WHERE project_id = ?1 ORDER BY created_at")
        .bind(project_id.to_string())
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(row_to_env).collect())
}

pub async fn delete_env(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM environments WHERE id = ?1")
        .bind(id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

// ─────────────────────────── secrets ───────────────────────────

pub async fn upsert_secret(
    db: &Db,
    project_id: uuid::Uuid,
    env_id: uuid::Uuid,
    key: &str,
    value_enc: &EncryptedSecret,
    created_by: uuid::Uuid,
) -> Result<Secret> {
    let now = utc_now();

    // Try to find an existing (non-deleted) secret
    let existing = sqlx::query(
        "SELECT * FROM secrets WHERE project_id = ?1 AND env_id = ?2 AND key = ?3 AND deleted_at IS NULL",
    )
    .bind(project_id.to_string())
    .bind(env_id.to_string())
    .bind(key)
    .fetch_optional(db)
    .await?;

    match existing {
        Some(row) => {
            let id = uuid::Uuid::parse_str(row.get::<String, _>("id").as_str())
                .unwrap_or(uuid::Uuid::nil());
            let version: i64 = row.get("version");

            // Archive the old value into version history
            let old_enc: String = row.get("value_enc");
            sqlx::query(
                "INSERT INTO secret_versions (id, secret_id, version, value_enc, created_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(id.to_string())
            .bind(version)
            .bind(&old_enc)
            .bind(row.get::<String, _>("created_by"))
            .bind(row.get::<String, _>("created_at"))
            .execute(db)
            .await?;

            sqlx::query(
                "UPDATE secrets SET value_enc = ?2, version = ?3, updated_at = ?4 WHERE id = ?1",
            )
            .bind(id.to_string())
            .bind(enc_json(value_enc))
            .bind(version + 1)
            .bind(&now)
            .execute(db)
            .await?;
        }
        None => {
            let id = uuid::Uuid::now_v7();
            sqlx::query(
                "INSERT INTO secrets (id, project_id, env_id, key, value_enc, version, created_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?7)",
            )
            .bind(id.to_string())
            .bind(project_id.to_string())
            .bind(env_id.to_string())
            .bind(key)
            .bind(enc_json(value_enc))
            .bind(created_by.to_string())
            .bind(&now)
            .execute(db)
            .await?;
        }
    }

    get_secret(db, project_id, env_id, key).await
}

pub async fn get_secret(
    db: &Db,
    project_id: uuid::Uuid,
    env_id: uuid::Uuid,
    key: &str,
) -> Result<Secret> {
    let row = sqlx::query(
        "SELECT * FROM secrets WHERE project_id = ?1 AND env_id = ?2 AND key = ?3 AND deleted_at IS NULL",
    )
    .bind(project_id.to_string())
    .bind(env_id.to_string())
    .bind(key)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| pandapass_core::CoreError::NotFound(format!("secret '{}' not found", key)))?;

    let enc_s: String = row.get("value_enc");
    Ok(Secret {
        meta: row_to_secret_meta(&row),
        value_enc: dec_json(&enc_s),
    })
}

fn row_to_secret_meta(row: &SqliteRow) -> SecretMeta {
    SecretMeta {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        project_id: uuid::Uuid::parse_str(row.get::<String, _>("project_id").as_str())
            .unwrap_or(uuid::Uuid::nil()),
        env_id: uuid::Uuid::parse_str(row.get::<String, _>("env_id").as_str())
            .unwrap_or(uuid::Uuid::nil()),
        key: row.get("key"),
        version: row.get::<i64, _>("version") as i32,
        created_by: uuid::Uuid::parse_str(row.get::<String, _>("created_by").as_str())
            .unwrap_or(uuid::Uuid::nil()),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
        updated_at: parse_ts(&row.get::<String, _>("updated_at")),
        deleted_at: parse_opt_ts(row.get("deleted_at")),
    }
}

/// List secret metadata only — never returns values
pub async fn list_secret_metas(
    db: &Db,
    project_id: uuid::Uuid,
    env_id: uuid::Uuid,
) -> Result<Vec<SecretMeta>> {
    let rows = sqlx::query(
        "SELECT id, project_id, env_id, key, version, created_by, created_at, updated_at, deleted_at
         FROM secrets WHERE project_id = ?1 AND env_id = ?2 AND deleted_at IS NULL
         ORDER BY key",
    )
    .bind(project_id.to_string())
    .bind(env_id.to_string())
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(row_to_secret_meta).collect())
}

pub async fn soft_delete_secret(
    db: &Db,
    project_id: uuid::Uuid,
    env_id: uuid::Uuid,
    key: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE secrets SET deleted_at = ?4 WHERE project_id = ?1 AND env_id = ?2 AND key = ?3",
    )
    .bind(project_id.to_string())
    .bind(env_id.to_string())
    .bind(key)
    .bind(utc_now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_secret_versions(
    db: &Db,
    project_id: uuid::Uuid,
    env_id: uuid::Uuid,
    key: &str,
) -> Result<Vec<SecretVersion>> {
    let rows = sqlx::query(
        "SELECT sv.* FROM secret_versions sv
         JOIN secrets s ON s.id = sv.secret_id
         WHERE s.project_id = ?1 AND s.env_id = ?2 AND s.key = ?3
         ORDER BY sv.version DESC",
    )
    .bind(project_id.to_string())
    .bind(env_id.to_string())
    .bind(key)
    .fetch_all(db)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let enc_s: String = r.get("value_enc");
            SecretVersion {
                secret_id: uuid::Uuid::parse_str(r.get::<String, _>("secret_id").as_str())
                    .unwrap_or(uuid::Uuid::nil()),
                version: r.get::<i64, _>("version") as i32,
                value_enc: dec_json(&enc_s),
                created_by: uuid::Uuid::parse_str(r.get::<String, _>("created_by").as_str())
                    .unwrap_or(uuid::Uuid::nil()),
                created_at: parse_ts(&r.get::<String, _>("created_at")),
            }
        })
        .collect())
}

/// Every encrypted secret in the system — used for master key rotation
pub async fn all_secrets(db: &Db) -> Result<Vec<Secret>> {
    let rows = sqlx::query("SELECT * FROM secrets WHERE deleted_at IS NULL")
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let enc_s: String = r.get("value_enc");
            Secret {
                meta: row_to_secret_meta(r),
                value_enc: dec_json(&enc_s),
            }
        })
        .collect())
}

// ─────────────────────────── envelopes ───────────────────────────

pub async fn put_envelope(
    db: &Db,
    user_id: uuid::Uuid,
    ciphertext: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO envelopes (id, user_id, ciphertext, created_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(user_id) DO UPDATE SET ciphertext = ?3, rotated_at = ?4",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(user_id.to_string())
    .bind(ciphertext)
    .bind(utc_now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_envelope(db: &Db, user_id: uuid::Uuid) -> Result<Option<Envelope>> {
    let row = sqlx::query("SELECT * FROM envelopes WHERE user_id = ?1")
        .bind(user_id.to_string())
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| Envelope {
        user_id: uuid::Uuid::parse_str(r.get::<String, _>("user_id").as_str())
            .unwrap_or(uuid::Uuid::nil()),
        ciphertext: r.get("ciphertext"),
        created_at: parse_ts(&r.get::<String, _>("created_at")),
        rotated_at: parse_opt_ts(r.get("rotated_at")),
    }))
}

pub async fn delete_envelope(db: &Db, user_id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM envelopes WHERE user_id = ?1")
        .bind(user_id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_envelope_users(db: &Db) -> Result<Vec<uuid::Uuid>> {
    let rows = sqlx::query("SELECT user_id FROM envelopes")
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| uuid::Uuid::parse_str(r.get::<String, _>("user_id").as_str()).ok())
        .collect())
}

// ─────────────────────────── service tokens ───────────────────────────

pub async fn create_service_token(db: &Db, token: &ServiceToken) -> Result<()> {
    let scopes: Vec<&str> = token.scopes.iter().map(|s| s.as_str()).collect();
    sqlx::query(
        "INSERT INTO service_tokens (id, name, token_hash, project_id, env_id, scopes, expires_at, created_by, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(token.id.to_string())
    .bind(&token.name)
    .bind(&token.token_hash)
    .bind(token.project_id.map(|v| v.to_string()))
    .bind(token.env_id.map(|v| v.to_string()))
    .bind(serde_json::to_string(&scopes).unwrap_or_default())
    .bind(opt_ts(token.expires_at))
    .bind(token.created_by.to_string())
    .bind(ts(token.created_at))
    .execute(db)
    .await?;
    Ok(())
}

fn row_to_token(row: &SqliteRow) -> ServiceToken {
    let scopes_s: String = row.get("scopes");
    let scopes: Vec<TokenScope> = serde_json::from_str::<Vec<String>>(&scopes_s)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| TokenScope::from_str(&s))
        .collect();

    ServiceToken {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        name: row.get("name"),
        token_hash: row.get("token_hash"),
        project_id: row
            .get::<Option<String>, _>("project_id")
            .and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        env_id: row
            .get::<Option<String>, _>("env_id")
            .and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        scopes,
        expires_at: parse_opt_ts(row.get("expires_at")),
        last_used_at: parse_opt_ts(row.get("last_used_at")),
        created_by: uuid::Uuid::parse_str(row.get::<String, _>("created_by").as_str())
            .unwrap_or(uuid::Uuid::nil()),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
        revoked_at: parse_opt_ts(row.get("revoked_at")),
    }
}

pub async fn get_token_by_hash(db: &Db, hash: &str) -> Result<Option<ServiceToken>> {
    let row = sqlx::query(
        "SELECT * FROM service_tokens WHERE token_hash = ?1 AND revoked_at IS NULL",
    )
    .bind(hash)
    .fetch_optional(db)
    .await?;
    Ok(row.as_ref().map(row_to_token))
}

pub async fn list_tokens(db: &Db, user_id: uuid::Uuid) -> Result<Vec<ServiceToken>> {
    let rows = sqlx::query("SELECT * FROM service_tokens WHERE created_by = ?1 ORDER BY created_at DESC")
        .bind(user_id.to_string())
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(row_to_token).collect())
}

pub async fn revoke_token(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE service_tokens SET revoked_at = ?2 WHERE id = ?1")
        .bind(id.to_string())
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn touch_token(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE service_tokens SET last_used_at = ?2 WHERE id = ?1")
        .bind(id.to_string())
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

// ─────────────────────────── sessions ───────────────────────────

pub async fn create_session(
    db: &Db,
    user_id: uuid::Uuid,
    token_hash: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
    ttl_days: i64,
) -> Result<Session> {
    let id = uuid::Uuid::now_v7();
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::days(ttl_days);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, created_at, expires_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6)",
    )
    .bind(id.to_string())
    .bind(user_id.to_string())
    .bind(token_hash)
    .bind(ip)
    .bind(user_agent)
    .bind(ts(now))
    .bind(ts(expires))
    .execute(db)
    .await?;

    Ok(Session {
        id,
        user_id,
        token_hash: token_hash.to_string(),
        ip: ip.map(String::from),
        user_agent: user_agent.map(String::from),
        created_at: now,
        expires_at: expires,
        last_seen_at: now,
    })
}

pub async fn get_session_by_hash(db: &Db, hash: &str) -> Result<Option<Session>> {
    let row = sqlx::query("SELECT * FROM sessions WHERE token_hash = ?1 AND expires_at > ?2")
        .bind(hash)
        .bind(utc_now())
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| Session {
        id: uuid::Uuid::parse_str(r.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        user_id: uuid::Uuid::parse_str(r.get::<String, _>("user_id").as_str())
            .unwrap_or(uuid::Uuid::nil()),
        token_hash: r.get("token_hash"),
        ip: r.get("ip"),
        user_agent: r.get("user_agent"),
        created_at: parse_ts(&r.get::<String, _>("created_at")),
        expires_at: parse_ts(&r.get::<String, _>("expires_at")),
        last_seen_at: parse_ts(&r.get::<String, _>("last_seen_at")),
    }))
}

pub async fn delete_session(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?1")
        .bind(id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_all_sessions(db: &Db, user_id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
        .bind(user_id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn cleanup_expired_sessions(db: &Db) -> Result<u64> {
    let r = sqlx::query("DELETE FROM sessions WHERE expires_at < ?1")
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(r.rows_affected())
}

// ─────────────────────────── audit queries ───────────────────────────

pub async fn query_audit(
    db: &Db,
    project_id: Option<uuid::Uuid>,
    user_id: Option<uuid::Uuid>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditLog>> {
    let rows = sqlx::query(
        "SELECT * FROM audit_log
         WHERE (?1 IS NULL OR project_id = ?1) AND (?2 IS NULL OR user_id = ?2)
         ORDER BY ts DESC
         LIMIT ?3 OFFSET ?4",
    )
    .bind(project_id.map(|v| v.to_string()))
    .bind(user_id.map(|v| v.to_string()))
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await?;

    Ok(rows.iter().map(row_to_audit).collect())
}

fn row_to_audit(row: &SqliteRow) -> AuditLog {
    let action_s: String = row.get("action");
    let outcome_s: String = row.get("outcome");
    AuditLog {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        ts: parse_ts(&row.get::<String, _>("ts")),
        user_id: row
            .get::<Option<String>, _>("user_id")
            .and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        action: AuditAction::from_str(&action_s),
        project_id: row
            .get::<Option<String>, _>("project_id")
            .and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        env_id: row
            .get::<Option<String>, _>("env_id")
            .and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        secret_key: row.get("secret_key"),
        ip: row.get("ip"),
        user_agent: row.get("user_agent"),
        outcome: match outcome_s.as_str() {
            "success" => AuditOutcome::Success,
            "failure" => AuditOutcome::Failure,
            "denied" => AuditOutcome::Denied,
            _ => AuditOutcome::Error,
        },
        meta: row
            .get::<Option<String>, _>("meta")
            .and_then(|s| serde_json::from_str(&s).ok()),
    }
}

pub async fn count_audit(db: &Db, project_id: Option<uuid::Uuid>) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) as c FROM audit_log WHERE (?1 IS NULL OR project_id = ?1)")
        .bind(project_id.map(|v| v.to_string()))
        .fetch_one(db)
        .await?;
    Ok(row.get::<i64, _>("c"))
}

/// Database-backed audit logger
pub struct DbAuditLogger {
    pool: SqlitePool,
}

impl DbAuditLogger {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl pandapass_core::AuditLogger for DbAuditLogger {
    async fn log(&self, entry: pandapass_core::models::AuditLog) -> Result<()> {
        let action_str = entry.action.as_str();
        let outcome_str = match entry.outcome {
            pandapass_core::models::AuditOutcome::Success => "success",
            pandapass_core::models::AuditOutcome::Failure => "failure",
            pandapass_core::models::AuditOutcome::Denied => "denied",
            pandapass_core::models::AuditOutcome::Error => "error",
        };

        sqlx::query(
            r#"
            INSERT INTO audit_log (id, ts, user_id, action, project_id, env_id, secret_key, ip, user_agent, outcome, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(entry.id.to_string())
        .bind(entry.ts.to_rfc3339())
        .bind(entry.user_id.map(|v| v.to_string()))
        .bind(action_str)
        .bind(entry.project_id.map(|v| v.to_string()))
        .bind(entry.env_id.map(|v| v.to_string()))
        .bind(entry.secret_key)
        .bind(entry.ip)
        .bind(entry.user_agent)
        .bind(outcome_str)
        .bind(entry.meta.map(|v| v.to_string()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ─────────────────────────── dynamic credentials (M2) ───────────────────────────

pub async fn create_dynamic_cred(
    db: &Db,
    project_id: uuid::Uuid,
    env_id: uuid::Uuid,
    kind: DynamicCredKind,
    username: &str,
    password_enc: &EncryptedSecret,
    ttl_seconds: i64,
    created_by: uuid::Uuid,
) -> Result<DynamicCred> {
    let id = uuid::Uuid::now_v7();
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_seconds);
    sqlx::query(
        "INSERT INTO dynamic_creds (id, project_id, env_id, kind, username, password_enc, ttl_seconds, issued_at, expires_at, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .bind(id.to_string())
    .bind(project_id.to_string())
    .bind(env_id.to_string())
    .bind(kind_str(kind))
    .bind(username)
    .bind(enc_json(password_enc))
    .bind(ttl_seconds)
    .bind(ts(now))
    .bind(ts(expires))
    .bind(created_by.to_string())
    .execute(db)
    .await?;
    get_dynamic_cred(db, id).await
}

fn kind_str(k: DynamicCredKind) -> &'static str {
    match k {
        DynamicCredKind::PostgreSQL => "postgresql",
        DynamicCredKind::MySQL => "mysql",
        DynamicCredKind::Redis => "redis",
    }
}

fn parse_kind(s: &str) -> DynamicCredKind {
    match s {
        "postgresql" => DynamicCredKind::PostgreSQL,
        "mysql" => DynamicCredKind::MySQL,
        _ => DynamicCredKind::Redis,
    }
}

pub async fn get_dynamic_cred(db: &Db, id: uuid::Uuid) -> Result<DynamicCred> {
    let row = sqlx::query("SELECT * FROM dynamic_creds WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("dynamic credential not found".into()))?;
    Ok(row_to_dynamic_cred(&row))
}

pub async fn list_dynamic_creds(
    db: &Db,
    project_id: uuid::Uuid,
    env_id: uuid::Uuid,
    include_revoked: bool,
) -> Result<Vec<DynamicCred>> {
    let rows = if include_revoked {
        sqlx::query("SELECT * FROM dynamic_creds WHERE project_id = ?1 AND env_id = ?2 ORDER BY issued_at DESC")
            .bind(project_id.to_string())
            .bind(env_id.to_string())
            .fetch_all(db)
            .await?
    } else {
        sqlx::query("SELECT * FROM dynamic_creds WHERE project_id = ?1 AND env_id = ?2 AND revoked_at IS NULL ORDER BY issued_at DESC")
            .bind(project_id.to_string())
            .bind(env_id.to_string())
            .fetch_all(db)
            .await?
    };
    Ok(rows.iter().map(row_to_dynamic_cred).collect())
}

pub async fn revoke_dynamic_cred(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE dynamic_creds SET revoked_at = ?2 WHERE id = ?1")
        .bind(id.to_string())
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn cleanup_expired_dynamic_creds(db: &Db) -> Result<u64> {
    let r = sqlx::query("DELETE FROM dynamic_creds WHERE expires_at < ?1 AND revoked_at IS NULL")
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(r.rows_affected())
}

/// List all active dynamic credentials across all projects/envs.
/// Used by the PostgreSQL proxy to find credentials by username.
pub async fn list_all_dynamic_creds(db: &Db) -> Result<Vec<DynamicCred>> {
    let rows = sqlx::query("SELECT * FROM dynamic_creds WHERE revoked_at IS NULL")
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(row_to_dynamic_cred).collect())
}

fn row_to_dynamic_cred(row: &SqliteRow) -> DynamicCred {
    let enc_s: String = row.get("password_enc");
    DynamicCred {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        project_id: uuid::Uuid::parse_str(row.get::<String, _>("project_id").as_str()).unwrap_or(uuid::Uuid::nil()),
        env_id: uuid::Uuid::parse_str(row.get::<String, _>("env_id").as_str()).unwrap_or(uuid::Uuid::nil()),
        kind: parse_kind(&row.get::<String, _>("kind")),
        username: row.get("username"),
        password_enc: dec_json(&enc_s),
        ttl_seconds: row.get::<i64, _>("ttl_seconds"),
        issued_at: parse_ts(&row.get::<String, _>("issued_at")),
        expires_at: parse_ts(&row.get::<String, _>("expires_at")),
        revoked_at: parse_opt_ts(row.get("revoked_at")),
        created_by: uuid::Uuid::parse_str(row.get::<String, _>("created_by").as_str()).unwrap_or(uuid::Uuid::nil()),
    }
}

// ─────────────────────────── policies (M3) ───────────────────────────

pub async fn create_policy(
    db: &Db,
    name: &str,
    rego_source: &str,
    created_by: uuid::Uuid,
) -> Result<Policy> {
    let id = uuid::Uuid::now_v7();
    let now = utc_now();
    sqlx::query(
        "INSERT INTO policies (id, name, rego_source, enabled, created_by, created_at, updated_at)
         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?5)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(rego_source)
    .bind(created_by.to_string())
    .bind(&now)
    .execute(db)
    .await?;
    get_policy(db, id).await
}

pub async fn get_policy(db: &Db, id: uuid::Uuid) -> Result<Policy> {
    let row = sqlx::query("SELECT * FROM policies WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("policy not found".into()))?;
    Ok(row_to_policy(&row))
}

pub async fn list_policies(db: &Db, enabled_only: bool) -> Result<Vec<Policy>> {
    let rows = if enabled_only {
        sqlx::query("SELECT * FROM policies WHERE enabled = 1 ORDER BY created_at DESC")
            .fetch_all(db)
            .await?
    } else {
        sqlx::query("SELECT * FROM policies ORDER BY created_at DESC")
            .fetch_all(db)
            .await?
    };
    Ok(rows.iter().map(row_to_policy).collect())
}

pub async fn update_policy(
    db: &Db,
    id: uuid::Uuid,
    name: Option<&str>,
    rego_source: Option<&str>,
    enabled: Option<bool>,
) -> Result<()> {
    sqlx::query(
        "UPDATE policies SET name = COALESCE(?2, name), rego_source = COALESCE(?3, rego_source), enabled = COALESCE(?4, enabled), updated_at = ?5 WHERE id = ?1",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(rego_source)
    .bind(enabled.map(|v| if v { 1 } else { 0 }))
    .bind(utc_now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_policy(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM policies WHERE id = ?1")
        .bind(id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

fn row_to_policy(row: &SqliteRow) -> Policy {
    Policy {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        name: row.get("name"),
        rego_source: row.get("rego_source"),
        enabled: row.get::<i64, _>("enabled") != 0,
        created_by: uuid::Uuid::parse_str(row.get::<String, _>("created_by").as_str()).unwrap_or(uuid::Uuid::nil()),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
        updated_at: parse_ts(&row.get::<String, _>("updated_at")),
    }
}

pub async fn bind_policy(
    db: &Db,
    policy_id: uuid::Uuid,
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
) -> Result<PolicyBinding> {
    let id = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO policy_bindings (id, policy_id, project_id, env_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(id.to_string())
    .bind(policy_id.to_string())
    .bind(project_id.map(|v| v.to_string()))
    .bind(env_id.map(|v| v.to_string()))
    .bind(utc_now())
    .execute(db)
    .await?;
    get_policy_binding(db, id).await
}

pub async fn get_policy_binding(db: &Db, id: uuid::Uuid) -> Result<PolicyBinding> {
    let row = sqlx::query("SELECT * FROM policy_bindings WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("policy binding not found".into()))?;
    Ok(row_to_policy_binding(&row))
}

pub async fn list_policy_bindings(
    db: &Db,
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
) -> Result<Vec<PolicyBinding>> {
    let rows = sqlx::query(
        "SELECT * FROM policy_bindings WHERE (?1 IS NULL OR project_id = ?1) AND (?2 IS NULL OR env_id = ?2) ORDER BY created_at",
    )
    .bind(project_id.map(|v| v.to_string()))
    .bind(env_id.map(|v| v.to_string()))
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(row_to_policy_binding).collect())
}

pub async fn delete_policy_binding(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("DELETE FROM policy_bindings WHERE id = ?1")
        .bind(id.to_string())
        .execute(db)
        .await?;
    Ok(())
}

fn row_to_policy_binding(row: &SqliteRow) -> PolicyBinding {
    PolicyBinding {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        policy_id: uuid::Uuid::parse_str(row.get::<String, _>("policy_id").as_str()).unwrap_or(uuid::Uuid::nil()),
        project_id: row.get::<Option<String>, _>("project_id").and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        env_id: row.get::<Option<String>, _>("env_id").and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
    }
}

// ──���────────���─────────────── PKI/CA (M4) ───────────────────────────

pub async fn create_ca_key(
    db: &Db,
    kind: CaKeyType,
    key_enc: &EncryptedSecret,
    cert_pem: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
    created_by: uuid::Uuid,
) -> Result<CaKey> {
    let id = uuid::Uuid::now_v7();
    let now = utc_now();
    sqlx::query(
        "INSERT INTO ca_keys (id, type, key_enc, cert_pem, not_before, not_after, created_by, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(id.to_string())
    .bind(ca_key_type_str(kind))
    .bind(enc_json(key_enc))
    .bind(cert_pem)
    .bind(ts(not_before))
    .bind(ts(not_after))
    .bind(created_by.to_string())
    .bind(&now)
    .execute(db)
    .await?;
    get_ca_key(db, id).await
}

fn ca_key_type_str(k: CaKeyType) -> &'static str {
    match k {
        CaKeyType::Root => "root",
        CaKeyType::Intermediate => "intermediate",
    }
}

fn parse_ca_key_type(s: &str) -> CaKeyType {
    match s {
        "root" => CaKeyType::Root,
        _ => CaKeyType::Intermediate,
    }
}

pub async fn get_ca_key(db: &Db, id: uuid::Uuid) -> Result<CaKey> {
    let row = sqlx::query("SELECT * FROM ca_keys WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("CA key not found".into()))?;
    Ok(row_to_ca_key(&row))
}

pub async fn list_ca_keys(db: &Db, include_revoked: bool) -> Result<Vec<CaKey>> {
    let rows = if include_revoked {
        sqlx::query("SELECT * FROM ca_keys ORDER BY created_at DESC")
            .fetch_all(db)
            .await?
    } else {
        sqlx::query("SELECT * FROM ca_keys WHERE revoked_at IS NULL ORDER BY created_at DESC")
            .fetch_all(db)
            .await?
    };
    Ok(rows.iter().map(row_to_ca_key).collect())
}

pub async fn revoke_ca_key(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE ca_keys SET revoked_at = ?2 WHERE id = ?1")
        .bind(id.to_string())
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

fn row_to_ca_key(row: &SqliteRow) -> CaKey {
    let enc_s: String = row.get("key_enc");
    CaKey {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        kind: parse_ca_key_type(&row.get::<String, _>("type")),
        key_enc: dec_json(&enc_s),
        cert_pem: row.get("cert_pem"),
        not_before: parse_ts(&row.get::<String, _>("not_before")),
        not_after: parse_ts(&row.get::<String, _>("not_after")),
        created_by: uuid::Uuid::parse_str(row.get::<String, _>("created_by").as_str()).unwrap_or(uuid::Uuid::nil()),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
        revoked_at: parse_opt_ts(row.get("revoked_at")),
    }
}

// ─────────────────────────── SSH certificates (M4) ───────────────────────────

pub async fn create_ssh_cert(
    db: &Db,
    user_id: uuid::Uuid,
    project_id: Option<uuid::Uuid>,
    principal: &str,
    cert_pem: &str,
    key_type: SshKeyType,
    valid_before: chrono::DateTime<chrono::Utc>,
    valid_after: chrono::DateTime<chrono::Utc>,
    created_by: uuid::Uuid,
) -> Result<SshCert> {
    let id = uuid::Uuid::now_v7();
    let now = utc_now();
    sqlx::query(
        "INSERT INTO ssh_certs (id, user_id, project_id, principal, cert_pem, key_type, valid_before, valid_after, created_by, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .bind(id.to_string())
    .bind(user_id.to_string())
    .bind(project_id.map(|v| v.to_string()))
    .bind(principal)
    .bind(cert_pem)
    .bind(ssh_key_type_str(key_type))
    .bind(ts(valid_before))
    .bind(ts(valid_after))
    .bind(created_by.to_string())
    .bind(&now)
    .execute(db)
    .await?;
    get_ssh_cert(db, id).await
}

fn ssh_key_type_str(k: SshKeyType) -> &'static str {
    match k {
        SshKeyType::Rsa => "rsa",
        SshKeyType::Ed25519 => "ed25519",
    }
}

fn parse_ssh_key_type(s: &str) -> SshKeyType {
    match s {
        "rsa" => SshKeyType::Rsa,
        _ => SshKeyType::Ed25519,
    }
}

pub async fn get_ssh_cert(db: &Db, id: uuid::Uuid) -> Result<SshCert> {
    let row = sqlx::query("SELECT * FROM ssh_certs WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db)
        .await
        .map_err(|_| pandapass_core::CoreError::NotFound("SSH certificate not found".into()))?;
    Ok(row_to_ssh_cert(&row))
}

pub async fn list_ssh_certs(
    db: &Db,
    user_id: Option<uuid::Uuid>,
    project_id: Option<uuid::Uuid>,
    include_revoked: bool,
) -> Result<Vec<SshCert>> {
    let rows = sqlx::query(
        "SELECT * FROM ssh_certs WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR project_id = ?2) AND (?3 = 1 OR revoked_at IS NULL) ORDER BY created_at DESC",
    )
    .bind(user_id.map(|v| v.to_string()))
    .bind(project_id.map(|v| v.to_string()))
    .bind(if include_revoked { 1 } else { 0 })
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(row_to_ssh_cert).collect())
}

pub async fn revoke_ssh_cert(db: &Db, id: uuid::Uuid) -> Result<()> {
    sqlx::query("UPDATE ssh_certs SET revoked_at = ?2 WHERE id = ?1")
        .bind(id.to_string())
        .bind(utc_now())
        .execute(db)
        .await?;
    Ok(())
}

fn row_to_ssh_cert(row: &SqliteRow) -> SshCert {
    SshCert {
        id: uuid::Uuid::parse_str(row.get::<String, _>("id").as_str()).unwrap_or(uuid::Uuid::nil()),
        user_id: uuid::Uuid::parse_str(row.get::<String, _>("user_id").as_str()).unwrap_or(uuid::Uuid::nil()),
        project_id: row.get::<Option<String>, _>("project_id").and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        principal: row.get("principal"),
        cert_pem: row.get("cert_pem"),
        key_type: parse_ssh_key_type(&row.get::<String, _>("key_type")),
        valid_before: parse_ts(&row.get::<String, _>("valid_before")),
        valid_after: parse_ts(&row.get::<String, _>("valid_after")),
        revoked_at: parse_opt_ts(row.get("revoked_at")),
        created_by: uuid::Uuid::parse_str(row.get::<String, _>("created_by").as_str()).unwrap_or(uuid::Uuid::nil()),
        created_at: parse_ts(&row.get::<String, _>("created_at")),
    }
}
