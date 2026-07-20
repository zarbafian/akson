//! Live checks (network, `#[ignore]`) for the public-processor CA path
//! (`ca_client_config`, design §9.1): the Mozilla CA roots + the pure-Rust
//! rustls-rustcrypto provider validate a real CA-signed chain and reject an
//! untrusted (self-signed) one.
//!
//! These need outbound TCP 443, so they are ignored by default. Run them with:
//!   cargo test -p akson-transport --test ca_tls -- --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use akson_transport::tls::ca_client_config;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Attempts a TLS 1.3 handshake to `host:443` under the CA-validating client
/// config. `Ok` means the server's certificate chained to a trusted root and
/// matched the name; `Err` carries the failure reason.
async fn handshake(host: &str) -> Result<(), String> {
    let config = ca_client_config().map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, 443))
        .await
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    tls.flush().await.ok();
    Ok(())
}

#[tokio::test]
#[ignore = "needs outbound network (TCP 443)"]
async fn ca_config_accepts_a_real_public_ca_chain() {
    handshake("example.com")
        .await
        .expect("a real CA-signed chain must validate against the Mozilla roots");
}

#[tokio::test]
#[ignore = "needs outbound network (TCP 443)"]
async fn ca_config_rejects_an_untrusted_self_signed_server() {
    let result = handshake("self-signed.badssl.com").await;
    assert!(
        result.is_err(),
        "a self-signed cert must NOT validate against the CA roots, got {result:?}"
    );
}
