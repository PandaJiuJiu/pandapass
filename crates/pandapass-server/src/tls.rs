//! Optional TLS transport (Step 2).
//!
//! The server can terminate TLS using a self-signed CA + leaf that it
//! generates at first boot (see `init_tls_storage` in `main.rs`). Clients
//! pin the CA via `GET /api/v1/ca.pem` (TOFU). When TLS is not configured,
//! the server keeps serving plain HTTP so existing deployments are unaffected.

use std::sync::Arc;

use anyhow::Context;
use rustls_pki_types::pem::PemObject;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

/// An `axum::serve::Listener` that terminates TLS on every accepted TCP
/// connection. Wrapping the plain `TcpListener` keeps axum's graceful
/// shutdown, connection info and error handling intact.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Build a TLS listener from the configured cert/key/CA files.
    ///
    /// Returns `None` when TLS is not fully configured (any of the three
    /// paths missing). The cert file may contain a chain; the first certificate
    /// is the leaf presented to clients.
    pub async fn bind(listen_addr: &str) -> anyhow::Result<Option<Self>> {
        let cert_file = std::env::var("PANDAPASS_TLS_CERT_FILE")
            .ok()
            .filter(|s| !s.is_empty());
        let key_file = std::env::var("PANDAPASS_TLS_KEY_FILE")
            .ok()
            .filter(|s| !s.is_empty());
        let ca_file = std::env::var("PANDAPASS_TLS_CA_FILE")
            .ok()
            .filter(|s| !s.is_empty());

        let (Some(cert_file), Some(key_file), Some(ca_file)) = (cert_file, key_file, ca_file)
        else {
            return Ok(None);
        };
        let inner = TcpListener::bind(listen_addr).await?;
        Self::from_listener(inner, &cert_file, &key_file, &ca_file)
            .await
            .map(Some)
    }

    /// Build a TLS listener around an already-bound TCP listener. Use this
    /// when the port must be reserved exactly once (e.g. when the plain
    /// listener is bound first and the TLS listener wraps it).
    pub async fn from_listener(
        inner: TcpListener,
        cert_file: &str,
        key_file: &str,
        ca_file: &str,
    ) -> anyhow::Result<Self> {
        // Install the ring crypto provider exactly once per process. A concurrent
        // install is fine: `install_default` returns the existing provider as an
        // error, which we treat as success.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }

        let _ = ca_file; // used only by callers (e.g. /api/v1/ca.pem)

        let cert_pem = std::fs::read(cert_file).context("read TLS cert file")?;
        let key_pem = std::fs::read(key_file).context("read TLS key file")?;

        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_slice_iter(&cert_pem)
                .map(|r| r.map(|c| c.into_owned()))
                .collect::<Result<Vec<_>, _>>()
                .context("parse TLS cert PEM")?;
        if certs.is_empty() {
            anyhow::bail!("TLS cert file contains no certificates");
        }
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
            .context("parse TLS key PEM")?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("build TLS config")?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        Ok(Self { inner, acceptor })
    }

    /// Like [`bind`](Self::bind) but with explicit file paths, so callers can
    /// wire up TLS without relying on process-global environment variables
    /// (useful in tests where several servers run concurrently).
    pub async fn bind_with_paths(
        listen_addr: &str,
        cert_file: &str,
        key_file: &str,
        ca_file: &str,
    ) -> anyhow::Result<Self> {
        let inner = TcpListener::bind(listen_addr).await?;
        Self::from_listener(inner, cert_file, key_file, ca_file).await
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(t) => t,
                Err(e) => {
                    // Match axum's own handling: connection errors are retried
                    // silently, other errors are logged and retried after 1s.
                    if e.kind() == std::io::ErrorKind::ConnectionRefused
                        || e.kind() == std::io::ErrorKind::ConnectionAborted
                        || e.kind() == std::io::ErrorKind::ConnectionReset
                    {
                        continue;
                    }
                    tracing::error!("accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, addr),
                Err(_) => continue, // TLS handshake failed; drop and retry.
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}