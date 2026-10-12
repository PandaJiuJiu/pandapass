//! Redis wire protocol proxy for dynamic credentials (M2, D8).
//!
//! This implements a minimal Redis proxy that:
//! 1. Accepts client connections on a configured port
//! 2. Parses RESP `AUTH <username> <password>` (or legacy `AUTH <password>`)
//! 3. Looks up the dynamic credential in the database by username
//! 4. If valid (not revoked, not expired, kind = Redis), forwards the
//!    connection to upstream Redis and relays bytes bidirectionally
//! 5. If invalid/expired, replies with a RESP error and closes
//!
//! Unlike the PostgreSQL proxy, Redis has no startup handshake: the client sends
//! an `AUTH` command and the upstream Redis answers `+OK`. We intercept the first
//! `AUTH`, validate the credential against our database, then replay the same
//! `AUTH` upstream so the upstream Redis performs its own authentication with the
//! same dynamic credential. After that the connection is a transparent byte
//! relay.
//!
//! Clients that send a non-AUTH first command (e.g. `PING`) are relayed as-is: the
//! proxy only enforces a credential when the client supplies one, matching Redis
//! semantics where `requirepass` is optional.

use anyhow::{Context, Result};
use pandapass_core::crypto::constant_time_eq;
use pandapass_core::models::{DynamicCred, DynamicCredKind};
use pandapass_db::Db;
use secrecy::ExposeSecret;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{error, info, warn};

/// How long a client may take to complete the Redis handshake (`AUTH`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration for the Redis dynamic credential proxy.
#[derive(Clone)]
pub struct RedisProxyConfig {
    pub listen_addr: SocketAddr,
    pub db: Db,
    /// Address of the upstream Redis server.
    pub upstream_addr: SocketAddr,
    /// The server's own age identity, used to unwrap the creator's envelope
    /// and decrypt the stored credential password.
    pub server_age_identity: String,
}

/// Decrypt a dynamic credential password using the creator's master key.
/// Mirrors `dynamic_proxy::decrypt_cred_password`.
async fn decrypt_cred_password(
    db: &Db,
    server_age_identity: &str,
    cred: &DynamicCred,
) -> Result<Option<String>> {
    use pandapass_db::get_envelope;

    let envelope = match get_envelope(db, cred.created_by).await? {
        Some(e) => e,
        None => return Ok(None),
    };

    let mk = envelope
        .decrypt(server_age_identity)
        .map_err(|_| anyhow::anyhow!("envelope not sealed to server"))?;

    let password = cred.password_enc.decrypt_with_purpose(
        &mk,
        pandapass_core::crypto::key_purpose::DYNAMIC_CRED_PASSWORD,
    )?;
    Ok(Some(password.expose_secret().to_string()))
}

/// Build a Redis RESP error line, e.g. `-ERR invalid dynamic credential\r\n`.
fn build_resp_error(message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(message.len() + 6);
    buf.push(b'-');
    buf.extend_from_slice(message.as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf
}

/// A parsed RESP `AUTH` command.
struct AuthCommand {
    /// The credential username. `None` for legacy single-argument
    /// `AUTH <password>` (no username), which we reject because dynamic
    /// credentials always have a username.
    username: Option<String>,
    password: String,
}

/// Parse a RESP inline array from a client command. The first token is the
/// command name (uppercased), the rest are arguments.
///
/// Only the simplest form is supported: `*3\r\n$4\r\nAUTH\r\n$..\r\n..\r\n`.
/// A real Redis client sends exactly this for `AUTH user pass` (or
/// `*2\r\n$4\r\nAUTH\r\n$..\r\n..\r\n` for legacy `AUTH pass`).
///
/// Returns `Ok(None)` if the client sent a non-AUTH command.
fn parse_auth_command(buf: &[u8]) -> Result<Option<AuthCommand>> {
    // Split on \r\n into RESP frames. The first frame is the array header
    // `*N`, then `$len` bulk strings. We only need the first few tokens.
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() && tokens.len() < 3 {
        // Find the end of this line.
        let Some(cr) = buf[pos..].iter().position(|&b| b == b'\r') else {
            break;
        };
        let line = &buf[pos..pos + cr];
        pos += cr + 2; // skip \r\n

        if line.is_empty() {
            continue;
        }

        match line[0] {
            b'*' => {
                // Array header: *<count>
                let _count: usize = std::str::from_utf8(&line[1..])
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                // No token value; continue to next line.
            }
            b'$' => {
                // Bulk string: $<len>; the value follows on the next line.
                let len: usize = std::str::from_utf8(&line[1..])
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if pos + len > buf.len() {
                    break;
                }
                let val = String::from_utf8_lossy(&buf[pos..pos + len]).to_string();
                pos += len;
                // skip trailing \r\n
                if pos + 2 <= buf.len() {
                    pos += 2;
                }
                tokens.push(val);
            }
            _ => {
                // Inline command line (telnet style): first token is command.
                let text = std::str::from_utf8(line).unwrap_or("");
                tokens.push(text.to_string());
                // Inline commands have no further frames.
                break;
            }
        }
    }

    if tokens.is_empty() {
        return Ok(None);
    }

    let command = tokens[0].to_uppercase();
    if command != "AUTH" {
        return Ok(None);
    }

    // AUTH has 1 or 2 arguments: `AUTH <password>` (legacy) or
    // `AUTH <username> <password>`.
    match tokens.len() {
        2 => Ok(Some(AuthCommand {
            username: None,
            password: tokens[1].clone(),
        })),
        3 => Ok(Some(AuthCommand {
            username: Some(tokens[1].clone()),
            password: tokens[2].clone(),
        })),
        _ => Ok(None),
    }
}

/// Look up a live Redis dynamic credential by username and decrypt its
/// password. Returns `None` if no active Redis credential matches.
async fn find_redis_cred(
    db: &Db,
    server_age_identity: &str,
    username: &str,
) -> Result<Option<(DynamicCred, String)>> {
    let creds = pandapass_db::list_all_dynamic_creds(db).await?;
    let cred = creds
        .into_iter()
        .find(|c| c.username == username && c.revoked_at.is_none());

    let Some(cred) = cred else {
        return Ok(None);
    };

    if chrono::Utc::now() > cred.expires_at {
        warn!("Dynamic credential expired for user: {}", username);
        return Ok(None);
    }

    if !matches!(cred.kind, DynamicCredKind::Redis) {
        warn!(
            "Non-Redis credential used for Redis proxy: {}",
            cred.kind.as_str()
        );
        return Ok(None);
    }

    let password = decrypt_cred_password(db, server_age_identity, &cred)
        .await?
        .unwrap_or_default();
    Ok(Some((cred, password)))
}

/// Handle a single client connection.
async fn handle_connection(
    mut client: TcpStream,
    config: RedisProxyConfig,
    peer_addr: SocketAddr,
) -> Result<()> {
    info!("New Redis proxy connection from {}", peer_addr);

    // Read the client's first command bytes, up to 8 KiB. Redis commands are
    // small; anything larger is malformed and will be rejected.
    let mut first = vec![0u8; 8192];
    let n = timeout(HANDSHAKE_TIMEOUT, client.read(&mut first))
        .await
        .context("handshake timeout reading first command")?
        .context("read first command")?;
    if n == 0 {
        return Ok(());
    }
    first.truncate(n);

    // Determine whether this is an AUTH command. If so, validate the
    // credential. The original `first` bytes are replayed to the upstream
    // verbatim (see below), so we never need to reconstruct the command.
    let auth = parse_auth_command(&first)?;

    if let Some(auth) = auth {
        let Some(username) = auth.username else {
            // Legacy `AUTH <password>` without a username: dynamic credentials
            // always have a username, so refuse.
            client
                .write_all(&build_resp_error("ERR invalid dynamic credential"))
                .await?;
            client.flush().await?;
            return Ok(());
        };

        let (cred, password) =
            match find_redis_cred(&config.db, &config.server_age_identity, &username).await? {
                Some(found) => found,
                None => {
                    client
                        .write_all(&build_resp_error("ERR invalid dynamic credential"))
                        .await?;
                    client.flush().await?;
                    return Ok(());
                }
            };
        let _ = cred;

        if !constant_time_eq(auth.password.as_bytes(), password.as_bytes()) {
            warn!("Password mismatch for user: {}", username);
            client
                .write_all(&build_resp_error("ERR invalid password"))
                .await?;
            client.flush().await?;
            return Ok(());
        }

        info!("Authenticated dynamic credential for user: {}", username);
    }

    // Connect to the upstream Redis.
    let mut upstream = TcpStream::connect(config.upstream_addr)
        .await
        .context("connect to upstream Redis")?;
    info!("Connected to upstream Redis at {}", config.upstream_addr);

    // Replay the client's first command bytes upstream. If the client
    // authenticated with a dynamic credential, this forwards the original AUTH
    // command so the upstream Redis authenticates the same credential.
    upstream.write_all(&first).await?;
    upstream.flush().await?;

    // If the client did NOT authenticate (no AUTH) but the upstream requires
    // a password, we have nothing to send — the upstream will reply with an
    // error that gets relayed back. That is correct behavior.

    // Bidirectional relay. After the first command is replayed, the
    // connection is a byte stream in both directions; the proxy moves bytes
    // without looking.
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    let c_to_u = tokio::io::copy(&mut cr, &mut uw);
    let u_to_c = tokio::io::copy(&mut ur, &mut cw);
    tokio::select! {
        r = c_to_u => if let Err(e) = r { warn!("client->upstream relay ended: {e}"); },
        r = u_to_c => if let Err(e) = r { warn!("upstream->client relay ended: {e}"); },
    }

    Ok(())
}

/// Run the Redis dynamic credential proxy server on an already-bound listener.
pub async fn run_redis_proxy(listener: TcpListener, config: RedisProxyConfig) -> Result<()> {
    let addr = listener.local_addr()?;
    info!("Dynamic credential Redis proxy listening on {}", addr);

    loop {
        let (client, peer_addr) = listener.accept().await?;
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, config, peer_addr).await {
                error!("Redis proxy connection error: {}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pandapass_core::crypto::{AgeIdentity, EncryptedSecret, Envelope, MasterKey, SealOptions};
    use pandapass_core::models::{DynamicCredKind, GlobalRole};
    use pandapass_db::{connect, migrate};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// Create a database with a user, an envelope sealed to the server, and
    /// one live Redis dynamic credential.
    async fn setup_db() -> (pandapass_db::Db, AgeIdentity, String, String) {
        let dir =
            std::env::temp_dir().join(format!("pp-redis-proxy-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_url = format!("sqlite://{}?mode=rwc", dir.join("test.db").display());
        let db = connect(&db_url).await.unwrap();
        migrate(&db).await.unwrap();

        let server = AgeIdentity::generate();
        let server_pub = server.public_key().unwrap();

        let user = pandapass_db::create_user(
            &db,
            "redis-proxy@test.local",
            "not-a-real-hash",
            GlobalRole::Admin,
        )
        .await
        .unwrap();

        let mk = MasterKey::generate();
        let envelope =
            Envelope::create(user.id, &mk, &server_pub, &SealOptions::default()).unwrap();
        pandapass_db::put_envelope(&db, user.id, &envelope.ciphertext)
            .await
            .unwrap();

        let project = pandapass_db::create_project(&db, "RedisProxy", "redisproxy", None, user.id)
            .await
            .unwrap();
        let env = pandapass_db::create_env(&db, project.id, "prod", "prod", None)
            .await
            .unwrap();

        let password_enc = EncryptedSecret::encrypt_with_purpose(
            "s3cret-redis-pass",
            &mk,
            pandapass_core::crypto::key_purpose::DYNAMIC_CRED_PASSWORD,
        )
        .unwrap();
        let cred = pandapass_db::create_dynamic_cred(
            &db,
            project.id,
            env.id,
            DynamicCredKind::Redis,
            "redis_user",
            &password_enc,
            3600,
            user.id,
        )
        .await
        .unwrap();

        (
            db,
            server,
            cred.username.clone(),
            "s3cret-redis-pass".to_string(),
        )
    }

    /// A fake upstream Redis server: reads the AUTH command, reports the
    /// received credentials over a channel, replies +OK, then echoes one
    /// chunk so the test can prove the byte stream relays.
    async fn spawn_fake_upstream() -> (SocketAddr, tokio::sync::mpsc::Receiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(sock);
            let mut line = String::new();
            // Read the RESP array line: *3\r\n
            reader.read_line(&mut line).await.unwrap();
            // Read the remaining bulk strings.
            let mut parts = Vec::new();
            for _ in 0..3 {
                let mut len_line = String::new();
                reader.read_line(&mut len_line).await.unwrap();
                let len: usize = len_line.trim_start_matches("$").trim().parse().unwrap();
                let mut val = vec![0u8; len];
                reader.read_exact(&mut val).await.unwrap();
                let mut crlf = [0u8; 2];
                reader.read_exact(&mut crlf).await.unwrap();
                parts.push(String::from_utf8_lossy(&val).to_string());
            }
            let _ = tx.send((parts[1].clone(), parts[2].clone())).await;

            // +OK
            let mut sock = reader.into_inner();
            sock.write_all(b"+OK\r\n").await.unwrap();

            // Echo one chunk so the test can prove the byte stream relays.
            let mut echo = [0u8; 4];
            sock.read_exact(&mut echo).await.unwrap();
            sock.write_all(&echo).await.unwrap();
        });
        (addr, rx)
    }

    /// Spawn the Redis proxy on a bound listener.
    async fn spawn_redis_proxy(
        config: RedisProxyConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            run_redis_proxy(listener, config).await.unwrap();
        });
        (addr, handle)
    }

    fn build_auth_command(username: &str, password: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"*3\r\n$4\r\nAUTH\r\n");
        buf.extend_from_slice(format!("${}\r\n{}\r\n", username.len(), username).as_bytes());
        buf.extend_from_slice(format!("${}\r\n{}\r\n", password.len(), password).as_bytes());
        buf
    }

    #[tokio::test]
    async fn redis_proxy_authenticates_and_relays_to_upstream() {
        let (db, server, username, password) = setup_db().await;
        let (upstream_addr, mut got_creds) = spawn_fake_upstream().await;

        let config = RedisProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            db,
            upstream_addr,
            server_age_identity: server.as_str().to_string(),
        };
        let (proxy_addr, proxy_handle) = spawn_redis_proxy(config).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&build_auth_command(&username, &password))
            .await
            .unwrap();

        // The proxy replies with the upstream's +OK (relayed).
        let mut resp = [0u8; 5];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"+OK\r\n", "expected +OK, got {:?}", &resp);

        // Prove the byte stream is a live relay, not a closed connection.
        client.write_all(b"PING").await.unwrap();
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"PING");

        // The upstream saw the stored username/password, not a guess.
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), got_creds.recv())
            .await
            .expect("upstream reported credentials")
            .unwrap();
        assert_eq!(received, (username.clone(), password));

        proxy_handle.abort();
    }

    #[tokio::test]
    async fn redis_proxy_wrong_password_is_rejected() {
        let (db, server, username, _password) = setup_db().await;
        let (upstream_addr, _rx) = spawn_fake_upstream().await;

        let config = RedisProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            db,
            upstream_addr,
            server_age_identity: server.as_str().to_string(),
        };
        let (proxy_addr, proxy_handle) = spawn_redis_proxy(config).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&build_auth_command(&username, "wrong-password"))
            .await
            .unwrap();

        // The proxy replies with a RESP error and closes.
        let mut resp = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut resp))
            .await
            .expect("read error response")
            .unwrap();
        let text = String::from_utf8_lossy(&resp[..n]);
        assert!(text.contains("invalid password"), "got: {text}");

        proxy_handle.abort();
    }

    #[tokio::test]
    async fn redis_proxy_expired_credential_is_refused() {
        let (db, server, username, _password) = setup_db().await;

        // Backdate the credential so TTL enforcement has something to catch.
        sqlx::query("UPDATE dynamic_creds SET expires_at = ?1 WHERE username = ?2")
            .bind("2020-01-01T00:00:00Z")
            .bind(&username)
            .execute(&db)
            .await
            .unwrap();

        let config = RedisProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            db,
            // Must not be reached — the proxy refuses before connecting.
            upstream_addr: "127.0.0.1:1".parse().unwrap(),
            server_age_identity: server.as_str().to_string(),
        };
        let (proxy_addr, proxy_handle) = spawn_redis_proxy(config).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&build_auth_command(&username, "any-password"))
            .await
            .unwrap();

        let mut resp = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut resp))
            .await
            .expect("read error response")
            .unwrap();
        let text = String::from_utf8_lossy(&resp[..n]);
        assert!(text.contains("invalid dynamic credential"), "got: {text}");

        proxy_handle.abort();
    }

    #[test]
    fn parse_auth_parses_bulk_command() {
        let cmd = build_auth_command("user", "pass");
        let auth = parse_auth_command(&cmd).unwrap().unwrap();
        assert_eq!(auth.username.as_deref(), Some("user"));
        assert_eq!(auth.password, "pass");
    }

    #[test]
    fn parse_auth_ignores_non_auth() {
        let ping = b"*1\r\n$4\r\nPING\r\n";
        let auth = parse_auth_command(ping).unwrap();
        assert!(auth.is_none());
    }

    #[test]
    fn build_resp_error_format() {
        let err = build_resp_error("ERR test error");
        assert_eq!(err[0], b'-');
        assert!(err.ends_with(b"\r\n"));
    }
}
