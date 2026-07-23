//! A minimal outbound A2A client (design §9.1): one pinned mutual-TLS POST.
//!
//! Both result delivery and proposal sending POST an A2A message to a paired
//! peer's endpoint, pinning that peer's endpoint certificate. This is that one
//! operation, shared: parse the `https` endpoint, present this endpoint's own
//! certificate, complete a TLS 1.3 mutual handshake pinned to the peer, POST the
//! body, and read the response (status + body). No redirects, no CA chain — the
//! peer is pinned exactly as at pairing.

use std::sync::Arc;

use akson_crypto::cert::EndpointCert;
use akson_crypto::identity::{Fingerprint, FingerprintKind};
use akson_crypto::keypair::PurposeKey;
use akson_store::delivery::content_digest;
use akson_transport::tls::client_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::control::Problem;

/// Cap on the peer's response body (design §9.1).
const MAX_RESPONSE_BODY: usize = 64 * 1024;

/// POSTs `body` as an A2A message to `endpoint_url` over mutual TLS pinned to
/// `pinned_fingerprint`, presenting `endpoint_cert` as the client certificate.
/// Returns the peer's response `(status, body)`. Only `https` endpoints are usable.
pub async fn post_a2a(
    endpoint_key: &PurposeKey,
    endpoint_cert: &EndpointCert,
    endpoint_url: &str,
    pinned_fingerprint: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), Problem> {
    let digest = content_digest(body);
    let (host, port, path) = parse_endpoint(endpoint_url).ok_or_else(|| {
        problem(
            500,
            "bad-endpoint",
            "the peer endpoint is not a usable https URL",
        )
    })?;
    let pinned = Fingerprint {
        kind: FingerprintKind::CertSha256,
        value: pinned_fingerprint.to_owned(),
    };
    let config = client_config(endpoint_key, endpoint_cert, &pinned)
        .map_err(|_| problem(500, "tls", "the client TLS config could not be built"))?;
    let connector = TlsConnector::from(Arc::new(config));

    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| {
            problem(
                502,
                "unreachable",
                "the peer endpoint could not be resolved",
            )
        })?
        .next()
        .ok_or_else(|| problem(502, "unreachable", "the peer endpoint did not resolve"))?;
    let tcp = TcpStream::connect(addr).await.map_err(|_| {
        problem(
            502,
            "unreachable",
            "the peer endpoint refused the connection",
        )
    })?;
    let server_name =
        ServerName::try_from(host).map_err(|_| problem(500, "bad-endpoint", "bad host name"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|_| problem(502, "tls-handshake", "the peer TLS handshake failed"))?;

    // Activate the full required Akson extension set (design §10.1): the
    // signed card advertises them as required, so every operation names them —
    // a conforming receiver refuses an unactivated request.
    let extensions = akson_ext::namespace::required_extension_uris().join(", ");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: akson\r\nContent-Type: application/a2a+json\r\n\
         a2a-version: 1.0\r\ncontent-digest: {digest}\r\na2a-extensions: {extensions}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let exchange = async {
        tls.write_all(request.as_bytes()).await?;
        tls.write_all(body).await?;
        tls.flush().await?;
        // Read the full response; the peer closes after it (Connection: close).
        // Tolerate a peer that closes without a TLS close_notify.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() >= MAX_RESPONSE_BODY {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        Ok::<_, std::io::Error>(raw)
    };
    let raw = exchange
        .await
        .map_err(|e| problem_detail(502, "peer-io", "the request to the peer failed", e))?;
    split_response(&raw).ok_or_else(|| problem(502, "peer-io", "the peer sent no HTTP response"))
}

/// Parses an endpoint URL into (host, port, path). Only `https` is usable.
pub fn parse_endpoint(endpoint: &str) -> Option<(String, u16, String)> {
    let url = Url::parse(endpoint).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?.to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    Some((host, port, path.to_owned()))
}

/// Splits an HTTP/1.1 response into (status code, body bytes).
fn split_response(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..sep]).ok()?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, raw[sep + 4..].to_vec()))
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_requires_https() {
        assert!(parse_endpoint("http://host/a2a").is_none());
        let (host, port, path) = parse_endpoint("https://host:9443/a2a").unwrap();
        assert_eq!((host.as_str(), port, path.as_str()), ("host", 9443, "/a2a"));
        let (_h, port, path) = parse_endpoint("https://host").unwrap();
        assert_eq!((port, path.as_str()), (443, "/"));
    }
}
