//! PostgreSQL wire protocol proxy for dynamic credentials (M2).
//!
//! This implements a minimal PostgreSQL proxy that:
//! 1. Accepts client connections on a configured port
//! 2. Parses the startup message to extract the username
//! 3. Looks up the dynamic credential in the database
//! 4. If valid and not expired, rewrites the password and forwards to upstream
//! 5. If invalid/expired, terminates with appropriate error
//!
//! This is the "minimum viable shape" from HANDOFF.md: a TCP listener that
//! makes TTL enforcement real rather than just a UI hint.

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

/// How long a client may take to complete the PostgreSQL handshake
/// (startup message + password). Once authenticated, the relay runs without
/// a timeout because queries can legitimately run for a long time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration for the dynamic credential proxy
#[derive(Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub db: Db,
    /// Address of the upstream PostgreSQL server
    pub upstream_addr: SocketAddr,
    /// The server's own age identity, used to unwrap the creator's envelope
    /// and decrypt the stored credential password.
    pub server_age_identity: String,
}

/// Parsed PostgreSQL startup message
struct StartupMessage {
    user: String,
    database: Option<String>,
    /// Raw bytes for forwarding to upstream once proxying is implemented
    /// (see the `handle_connection` TODO). Unused until then.
    #[allow(dead_code)]
    raw: Vec<u8>,
}

impl StartupMessage {
    /// Parse a PostgreSQL startup message (v3 protocol)
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            anyhow::bail!("startup message too short");
        }

        // First 4 bytes: length (including itself), big-endian
        let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < length {
            anyhow::bail!("incomplete startup message");
        }

        // Next 4 bytes: protocol version (typically 196608 = 3.0)
        let _protocol = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        // Rest: key-value pairs, null-terminated, ending with double null
        let mut user = String::new();
        let mut database = None;
        let mut i = 8;

        while i < length - 1 {
            // Read key
            let key_start = i;
            while i < length && buf[i] != 0 {
                i += 1;
            }
            if i >= length {
                break;
            }
            let key = std::str::from_utf8(&buf[key_start..i])?;
            i += 1; // skip null

            // Read value
            let val_start = i;
            while i < length && buf[i] != 0 {
                i += 1;
            }
            if i >= length {
                break;
            }
            let val = std::str::from_utf8(&buf[val_start..i])?;
            i += 1; // skip null

            match key {
                "user" => user = val.to_string(),
                "database" => database = Some(val.to_string()),
                _ => {} // ignore unknown parameters
            }
        }

        Ok(Self {
            user,
            database,
            raw: buf[..length].to_vec(),
        })
    }
}

/// PostgreSQL error response (for auth failures)
fn build_error_response(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(b'E'); // ErrorResponse
    let msg_start = buf.len();
    buf.extend_from_slice(&[0, 0, 0, 0]); // placeholder length
    buf.push(b'S');
    buf.extend_from_slice(severity.as_bytes());
    buf.push(0);
    buf.push(b'C');
    buf.extend_from_slice(code.as_bytes());
    buf.push(0);
    buf.push(b'M');
    buf.extend_from_slice(message.as_bytes());
    buf.push(0);
    buf.push(0); // terminator

    // The length field covers everything from itself to the end of the
    // message (type byte is excluded). `msg_start` is the index just after
    // the type byte, which is where the length field begins.
    let msg_len = (buf.len() - msg_start) as u32;
    buf[msg_start..msg_start + 4].copy_from_slice(&msg_len.to_be_bytes());
    buf
}

/// Build a password request (AuthenticationCleartextPassword = 3).
///
/// The message is `R` + length(8) + auth-code(3): the length covers itself
/// and the 4-byte auth code, matching what a real PostgreSQL client parses.
fn build_password_request() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(b'R');
    buf.extend_from_slice(&8u32.to_be_bytes());
    buf.extend_from_slice(&3u32.to_be_bytes());
    buf
}

/// Send a PostgreSQL message with length prefix
async fn send_message(stream: &mut TcpStream, msg: &[u8]) -> Result<()> {
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one full PostgreSQL message (type byte + 4-byte length + payload).
///
/// Both client-to-server messages (PasswordMessage, Query, ...) and
/// server-to-client messages (AuthenticationRequest, ParameterStatus, ...)
/// share this framing. The length includes itself but not the type byte.
async fn read_pg_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length < 4 {
        anyhow::bail!("invalid message length {length}");
    }
    let mut payload = vec![0u8; length - 4];
    stream.read_exact(&mut payload).await?;
    let mut msg = header.to_vec();
    msg.extend_from_slice(&payload);
    Ok(msg)
}

/// Decrypt a dynamic credential password using the creator's master key.
///
/// The credential's password is encrypted with the master key of the user who
/// created it (`created_by`). To decrypt, we need that user's master key, which
/// means opening their envelope with the server's age identity.
///
/// Returns `None` if the credential has no envelope; the caller must then
/// refuse the connection (we never fall back to allowing the request).
async fn decrypt_cred_password(
    db: &Db,
    server_age_identity: &str,
    cred: &DynamicCred,
) -> Result<Option<String>> {
    use pandapass_db::get_envelope;

    // Look up the creator's envelope
    let envelope = match get_envelope(db, cred.created_by).await? {
        Some(e) => e,
        None => return Ok(None), // no envelope = can't decrypt
    };

    // Unwrap with server's age identity
    let mk = envelope
        .decrypt(server_age_identity)
        .map_err(|_| anyhow::anyhow!("envelope not sealed to server"))?;

    // Decrypt the password
    let password = cred.password_enc.decrypt(&mk)?;
    Ok(Some(password.expose_secret().to_string()))
}

/// Handle a single client connection.
///
/// The proxy validates the dynamic credential (exists, not revoked, not
/// expired, kind = PostgreSQL) and checks the client's password against the
/// stored one. If those pass, it opens a connection to the upstream
/// PostgreSQL server, forwards the original startup message, answers the
/// upstream's password challenge with the stored credential, and then relays
/// bytes bidirectionally. This makes TTL enforcement real: once the
/// credential expires or is revoked, the proxy refuses new connections at
/// the handshake.
async fn handle_connection(
    mut client: TcpStream,
    config: ProxyConfig,
    peer_addr: SocketAddr,
) -> Result<()> {
    info!("New connection from {}", peer_addr);

    // First, read the initial 8 bytes to detect SSLRequest/GSSENCRequest.
    // These are 8-byte messages: 4-byte length (8) + 4-byte code.
    // If it's SSLRequest (80877103) or GSSENCRequest (80877104), we reply
    // with a single 'N' byte (not supported) and then read the actual startup
    // message.
    let mut initial = [0u8; 8];
    timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut initial))
        .await
        .context("handshake timeout reading initial message")?
        .context("read initial message")?;

    // Check if this is SSLRequest (80877103) or GSSENCRequest (80877104)
    let length = u32::from_be_bytes([initial[0], initial[1], initial[2], initial[3]]) as usize;
    let code = u32::from_be_bytes([initial[4], initial[5], initial[6], initial[7]]);

    let full_startup = if length == 8 && (code == 80877103 || code == 80877104) {
        // Reply with 'N' (SSL/SSSENC not supported)
        client.write_all(b"N").await?;
        client.flush().await?;
        info!(
            "Rejected {} request, waiting for startup message",
            if code == 80877103 {
                "SSLRequest"
            } else {
                "GSSENCRequest"
            }
        );

        // Now read the actual startup message
        let mut len_buf = [0u8; 4];
        timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut len_buf))
            .await
            .context("handshake timeout reading startup length")?
            .context("read startup length")?;
        let length = u32::from_be_bytes(len_buf) as usize;
        if !(8..=65536).contains(&length) {
            anyhow::bail!("invalid startup message length {length}");
        }
        let mut startup_raw = vec![0u8; length - 4];
        timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut startup_raw))
            .await
            .context("handshake timeout reading startup payload")?
            .context("read startup payload")?;
        let mut full = Vec::with_capacity(length);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&startup_raw);
        full
    } else {
        // This is already the startup message (length + payload).
        // We've already read 8 bytes (length + protocol), need to read the rest.
        if !(8..=65536).contains(&length) {
            anyhow::bail!("invalid startup message length {length}");
        }
        let mut startup_raw = vec![0u8; length - 8];
        timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut startup_raw))
            .await
            .context("handshake timeout reading startup payload")?
            .context("read startup payload")?;
        let mut full = Vec::with_capacity(length);
        full.extend_from_slice(&initial[..4]);
        full.extend_from_slice(&initial[4..8]);
        full.extend_from_slice(&startup_raw);
        full
    };

    let startup = StartupMessage::parse(&full_startup).context("parse startup message")?;
    info!(
        "Client requested user: {}, database: {:?}",
        startup.user, startup.database
    );

    // Look up dynamic credential by username across all projects.
    // Pick the first matching PostgreSQL credential that isn't revoked.
    // We check expiration and kind separately to return precise error messages.
    let creds = pandapass_db::list_all_dynamic_creds(&config.db).await?;
    let cred = creds
        .into_iter()
        .find(|c| c.username == startup.user && c.revoked_at.is_none());

    let Some(cred) = cred else {
        warn!("No active dynamic credential for user: {}", startup.user);
        let err = build_error_response("FATAL", "28P01", "invalid dynamic credential");
        timeout(HANDSHAKE_TIMEOUT, send_message(&mut client, &err))
            .await
            .ok();
        return Ok(());
    };

    // Check expiration
    if chrono::Utc::now() > cred.expires_at {
        warn!("Dynamic credential expired for user: {}", startup.user);
        let err = build_error_response("FATAL", "28P01", "credential expired");
        timeout(HANDSHAKE_TIMEOUT, send_message(&mut client, &err))
            .await
            .ok();
        return Ok(());
    }

    // Check kind is PostgreSQL
    if !matches!(cred.kind, DynamicCredKind::PostgreSQL) {
        warn!(
            "Non-PostgreSQL credential used for PG proxy: {}",
            cred.kind.as_str()
        );
        let err = build_error_response("FATAL", "28000", "credential type mismatch");
        timeout(HANDSHAKE_TIMEOUT, send_message(&mut client, &err))
            .await
            .ok();
        return Ok(());
    };

    // Decrypt the stored password using the creator's master key (per-connection, no cache).
    let decrypted_password =
        match decrypt_cred_password(&config.db, &config.server_age_identity, &cred).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                warn!("Could not decrypt credential for user: {}", startup.user);
                let err = build_error_response("FATAL", "28000", "credential decryption failed");
                timeout(HANDSHAKE_TIMEOUT, send_message(&mut client, &err))
                    .await
                    .ok();
                return Ok(());
            }
            Err(e) => {
                error!("Decryption error: {}", e);
                let err = build_error_response("FATAL", "28000", "credential decryption error");
                timeout(HANDSHAKE_TIMEOUT, send_message(&mut client, &err))
                    .await
                    .ok();
                return Ok(());
            }
        };

    // Request password from client
    timeout(
        HANDSHAKE_TIMEOUT,
        send_message(&mut client, &build_password_request()),
    )
    .await
    .context("handshake timeout sending password request")?
    .context("send password request")?;

    // Read password message with timeout
    let msg = timeout(HANDSHAKE_TIMEOUT, read_pg_message(&mut client))
        .await
        .context("handshake timeout reading password message")?
        .context("read password message")?;

    if msg.is_empty() || msg[0] != b'p' {
        let err = build_error_response("FATAL", "28P01", "expected password message");
        timeout(HANDSHAKE_TIMEOUT, send_message(&mut client, &err))
            .await
            .ok();
        return Ok(());
    }

    let client_password = String::from_utf8_lossy(&msg[5..])
        .trim_end_matches('\0')
        .to_string();

    // Verify client password matches decrypted credential password using constant-time comparison
    if !constant_time_eq(client_password.as_bytes(), decrypted_password.as_bytes()) {
        warn!("Password mismatch for user: {}", startup.user);
        let err = build_error_response("FATAL", "28P01", "invalid password");
        timeout(HANDSHAKE_TIMEOUT, send_message(&mut client, &err))
            .await
            .ok();
        return Ok(());
    }

    info!(
        "Authenticated dynamic credential for user: {}",
        startup.user
    );

    // Connect to the upstream PostgreSQL server.
    let mut upstream = TcpStream::connect(config.upstream_addr)
        .await
        .context("connect to upstream PostgreSQL")?;
    info!(
        "Connected to upstream PostgreSQL at {}",
        config.upstream_addr
    );

    // Forward the original startup message so the upstream sees the same
    // client the proxy authenticated.
    upstream.write_all(&full_startup).await?;
    upstream.flush().await?;

    // Handle the upstream's authentication response. The first backend
    // message is an AuthenticationRequest:
    //   - AuthenticationOk (code 0): nothing to inject; forward as-is.
    //   - AuthenticationCleartextPassword (code 3): send the stored password,
    //     then read the next backend message and forward it.
    //   - MD5/SASL: we cannot answer those challenges with the stored
    //     plaintext, so refuse clearly instead of hanging the client.
    let mut to_client = read_pg_message(&mut upstream).await?;
    if to_client[0] == b'R' && to_client.len() >= 9 {
        let code = u32::from_be_bytes([to_client[5], to_client[6], to_client[7], to_client[8]]);
        match code {
            0 => { /* AuthenticationOk — nothing to inject */ }
            3 => {
                let mut pwd = vec![b'p'];
                pwd.extend_from_slice(&((decrypted_password.len() + 5) as u32).to_be_bytes());
                pwd.extend_from_slice(decrypted_password.as_bytes());
                pwd.push(0);
                upstream.write_all(&pwd).await?;
                upstream.flush().await?;
                to_client = read_pg_message(&mut upstream).await?;
            }
            other => {
                warn!("Upstream requires unsupported auth method (code {other}); refusing");
                let err = build_error_response(
                    "FATAL",
                    "0A000",
                    "upstream auth method not supported by proxy",
                );
                send_message(&mut client, &err).await?;
                return Ok(());
            }
        }
    }
    client.write_all(&to_client).await?;

    // Bidirectional relay. After authentication the protocol is a byte
    // stream in both directions (queries, results, notices, SSL negotiation
    // already happened upstream) — the proxy's only remaining job is to
    // move bytes without looking at them.
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

/// Run the dynamic credential proxy server on an already-bound listener.
///
/// This allows the caller to bind first (and fail fast if the port is taken)
/// before spawning the proxy task.
pub async fn run_proxy(listener: TcpListener, config: ProxyConfig) -> Result<()> {
    let addr = listener.local_addr()?;
    info!("Dynamic credential proxy listening on {}", addr);

    loop {
        let (client, peer_addr) = listener.accept().await?;
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, config, peer_addr).await {
                error!("Connection error: {}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pandapass_core::crypto::{AgeIdentity, MasterKey};
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn startup_message_parse() {
        // PostgreSQL 3.0 startup message for user "testuser", database "testdb"
        // Length: 58 bytes (0x0000003a) — includes the 8-byte header.
        // After header: user\0testuser\0database\0testdb\0\0 (last \0 = double-null terminator)
        // 4 (length) + 4 (protocol) + 5 (user\0) + 9 (testuser\0) + 9 (database\0) + 7 (testdb\0) + 1 (\0) = 39
        let msg = vec![
            0x00, 0x00, 0x00, 0x27, // length = 39
            0x00, 0x03, 0x00, 0x00, // protocol = 196608
            b'u', b's', b'e', b'r', 0, b't', b'e', b's', b't', b'u', b's', b'e', b'r', 0, b'd',
            b'a', b't', b'a', b'b', b'a', b's', b'e', 0, b't', b'e', b's', b't', b'd', b'b', 0,
            0, // terminator (double-null)
        ];

        let parsed = StartupMessage::parse(&msg).unwrap();
        assert_eq!(parsed.user, "testuser");
        assert_eq!(parsed.database, Some("testdb".to_string()));
    }

    #[test]
    fn build_error_response_format() {
        let err = build_error_response("FATAL", "28P01", "test error");
        assert_eq!(err[0], b'E'); // ErrorResponse type
        assert!(err.len() > 8);
    }

    #[test]
    fn build_password_request_format() {
        let req = build_password_request();
        assert_eq!(req[0], b'R'); // Authentication message
        assert_eq!(req.len(), 9);
        // Length field covers itself + the auth code.
        assert_eq!(u32::from_be_bytes([req[1], req[2], req[3], req[4]]), 8);
        // AuthenticationCleartextPassword.
        assert_eq!(u32::from_be_bytes([req[5], req[6], req[7], req[8]]), 3);
    }

    /// Read one full PostgreSQL message (type byte + length + payload) from a
    /// socket. Mirrors the framing used by [`read_pg_message`].
    async fn read_pg_msg(sock: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut hdr = [0u8; 5];
        sock.read_exact(&mut hdr).await.unwrap();
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        let mut payload = vec![0u8; len - 4];
        sock.read_exact(&mut payload).await.unwrap();
        (hdr[0], payload)
    }

    // ── dynamic credential proxy: end-to-end tests ─────────────────────
    //
    // These exercise the full TCP path: a client connects to the proxy,
    // authenticates with the dynamic credential, and the proxy forwards to
    // a fake upstream PostgreSQL server. This is what turns the HANDOFF
    // acceptance criterion — "a connection with the same credential is refused
    // after the TTL" — into tested behaviour.

    fn build_startup_message(user: &str, database: &str) -> Vec<u8> {
        let mut body = vec![0u8, 3, 0, 0]; // protocol 3.0
        body.extend_from_slice(b"user");
        body.push(0);
        body.extend_from_slice(user.as_bytes());
        body.push(0);
        body.extend_from_slice(b"database");
        body.push(0);
        body.extend_from_slice(database.as_bytes());
        body.push(0);
        body.push(0); // double-null terminator
        let len = (body.len() + 4) as u32;
        let mut msg = Vec::with_capacity(len as usize);
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    fn build_password_message(password: &str) -> Vec<u8> {
        let mut msg = vec![b'p'];
        let len = (password.len() + 5) as u32; // 4 length + password + NUL
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(password.as_bytes());
        msg.push(0);
        msg
    }

    /// Create a database with a user, an envelope sealed to the server, and
    /// one live PostgreSQL dynamic credential.
    async fn setup_db() -> (pandapass_db::Db, AgeIdentity, String, String) {
        use pandapass_core::crypto::{EncryptedSecret, Envelope, SealOptions};
        use pandapass_core::models::{DynamicCredKind, GlobalRole};
        use pandapass_db::{connect, migrate};

        let dir = std::env::temp_dir().join(format!("pp-proxy-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_url = format!("sqlite://{}?mode=rwc", dir.join("test.db").display());
        let db = connect(&db_url).await.unwrap();
        migrate(&db).await.unwrap();

        let server = AgeIdentity::generate();
        let server_pub = server.public_key().unwrap();

        let user = pandapass_db::create_user(
            &db,
            "proxy@test.local",
            "not-a-real-hash",
            GlobalRole::Admin,
        )
        .await
        .unwrap();

        // Envelope: the user's master key, sealed only to the server (the
        // proxy must unwrap it to decrypt the credential password).
        let mk = MasterKey::generate();
        let envelope =
            Envelope::create(user.id, &mk, &server_pub, &SealOptions::default()).unwrap();
        pandapass_db::put_envelope(&db, user.id, &envelope.ciphertext)
            .await
            .unwrap();

        let project = pandapass_db::create_project(&db, "Proxy", "proxy", None, user.id)
            .await
            .unwrap();
        let env = pandapass_db::create_env(&db, project.id, "prod", "prod", None)
            .await
            .unwrap();

        let password_enc = EncryptedSecret::encrypt("s3cret-pass", &mk).unwrap();
        let cred = pandapass_db::create_dynamic_cred(
            &db,
            project.id,
            env.id,
            DynamicCredKind::PostgreSQL,
            "proxy_user",
            &password_enc,
            3600,
            user.id,
        )
        .await
        .unwrap();

        (db, server, cred.username.clone(), "s3cret-pass".to_string())
    }

    /// A fake upstream PostgreSQL server: answers the password challenge,
    /// reports the password it received over a channel, sends AuthenticationOk
    /// + ReadyForQuery, then echoes back one 4-byte chunk.
    async fn spawn_fake_upstream() -> (SocketAddr, tokio::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len - 4];
            sock.read_exact(&mut payload).await.unwrap();

            // AuthenticationCleartextPassword
            sock.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3])
                .await
                .unwrap();

            let mut header = [0u8; 5];
            sock.read_exact(&mut header).await.unwrap();
            let plen = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let mut pwd = vec![0u8; plen - 4];
            sock.read_exact(&mut pwd).await.unwrap();
            let _ = tx
                .send(
                    String::from_utf8_lossy(&pwd)
                        .trim_end_matches('\0')
                        .to_string(),
                )
                .await;

            // AuthenticationOk + ReadyForQuery
            sock.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0])
                .await
                .unwrap();
            sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']).await.unwrap();

            // Echo one chunk so the test can prove the byte stream relays.
            let mut echo = [0u8; 4];
            sock.read_exact(&mut echo).await.unwrap();
            sock.write_all(&echo).await.unwrap();
        });
        (addr, rx)
    }

    /// Accept connections on a bound listener and feed them to
    /// [`handle_connection`]. Returns the listen address and a handle to stop.
    async fn spawn_proxy(config: ProxyConfig) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            run_proxy(listener, config).await.unwrap();
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn proxy_authenticates_and_relays_to_upstream() {
        let (db, server, username, password) = setup_db().await;
        let (upstream_addr, mut got_password) = spawn_fake_upstream().await;

        let config = ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            db,
            upstream_addr,
            server_age_identity: server.as_str().to_string(),
        };
        let (proxy_addr, proxy_handle) = spawn_proxy(config).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&build_startup_message(&username, "proxydb"))
            .await
            .unwrap();

        // The proxy asks for a cleartext password (it validates the
        // credential before touching the upstream).
        let (msg_type, payload) = read_pg_msg(&mut client).await;
        assert_eq!(msg_type, b'R');
        let auth_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        assert_eq!(auth_code, 3);

        client
            .write_all(&build_password_message(&password))
            .await
            .unwrap();

        // Upstream's AuthenticationOk (relayed by the proxy).
        let (msg_type, payload) = read_pg_msg(&mut client).await;
        assert_eq!(msg_type, b'R');
        let auth_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        assert_eq!(auth_code, 0);
        // ReadyForQuery.
        let (msg_type, _payload) = read_pg_msg(&mut client).await;
        assert_eq!(msg_type, b'Z');

        // Prove the byte stream is a live relay, not a closed connection.
        client.write_all(b"PING").await.unwrap();
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"PING");

        // And the upstream saw the stored password, not the client's guess.
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), got_password.recv())
            .await
            .expect("upstream reported a password")
            .unwrap();
        assert_eq!(received, password);

        proxy_handle.abort();
    }

    #[tokio::test]
    async fn wrong_password_is_rejected_before_upstream() {
        let (db, server, username, _password) = setup_db().await;
        let (upstream_addr, _rx) = spawn_fake_upstream().await;

        let config = ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            db,
            upstream_addr,
            server_age_identity: server.as_str().to_string(),
        };
        let (proxy_addr, proxy_handle) = spawn_proxy(config).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&build_startup_message(&username, "proxydb"))
            .await
            .unwrap();

        let (msg_type, payload) = read_pg_msg(&mut client).await;
        assert_eq!(msg_type, b'R');
        let auth_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        assert_eq!(auth_code, 3);

        client
            .write_all(&build_password_message("wrong-password"))
            .await
            .unwrap();

        // FATAL error response, and no upstream connection is made.
        let (msg_type, payload) = read_pg_msg(&mut client).await;
        assert_eq!(msg_type, b'E');
        let text = String::from_utf8_lossy(&payload);
        assert!(text.contains("invalid password"), "got: {text}");

        proxy_handle.abort();
    }

    #[tokio::test]
    async fn expired_credential_is_refused_at_handshake() {
        let (db, server, username, _password) = setup_db().await;

        // Backdate the credential so TTL enforcement has something to catch.
        sqlx::query("UPDATE dynamic_creds SET expires_at = ?1 WHERE username = ?2")
            .bind("2020-01-01T00:00:00Z")
            .bind(&username)
            .execute(&db)
            .await
            .unwrap();

        let config = ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            db,
            // Must not be reached — the proxy refuses before connecting.
            upstream_addr: "127.0.0.1:1".parse().unwrap(),
            server_age_identity: server.as_str().to_string(),
        };
        let (proxy_addr, proxy_handle) = spawn_proxy(config).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&build_startup_message(&username, "proxydb"))
            .await
            .unwrap();

        let (msg_type, payload) = read_pg_msg(&mut client).await;
        assert_eq!(msg_type, b'E');
        let text = String::from_utf8_lossy(&payload);
        assert!(text.contains("credential expired"), "got: {text}");

        proxy_handle.abort();
    }
}
