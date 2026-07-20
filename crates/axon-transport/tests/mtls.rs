//! End-to-end proof that the pure-Rust TLS stack (rustls + rustls-rustcrypto,
//! ADR-0011) completes a TLS 1.3 mutual handshake with our self-signed Ed25519
//! endpoint certificates and fingerprint pinning (design §9.1), and fails
//! closed when the pin does not match.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use axon_crypto::cert::{self_signed_endpoint, EndpointCert};
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_transport::tls::{client_config, server_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn endpoint(seed: u8) -> (PurposeKey, EndpointCert) {
    let key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[seed; 32]);
    let cert = self_signed_endpoint(&key, "axon-endpoint", Duration::from_secs(86_400)).unwrap();
    (key, cert)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_round_trip_with_pinning() {
    let (a_key, a_cert) = endpoint(1); // server identity
    let (b_key, b_cert) = endpoint(2); // client identity

    // Each side pins the other's SHA-256/DER fingerprint.
    let server = server_config(&a_key, &a_cert, &b_cert.fingerprint).unwrap();
    let client = client_config(&b_key, &b_cert, &a_cert.fingerprint).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));

    let srv = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server handshake");
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        tls.write_all(b"pong").await.unwrap();
        tls.shutdown().await.ok();
    });

    let connector = TlsConnector::from(Arc::new(client));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(name, tcp)
        .await
        .expect("client handshake");
    tls.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    srv.await.unwrap();
}

/// A correctly-pinned but EXPIRED certificate must not authenticate, in either
/// direction. Pinning proves *which* key the peer holds; it says nothing about
/// whether the certificate is still current, so both verifiers check the validity
/// window at the handshake instant (design §9.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_certificate_fails_the_handshake_in_both_directions() {
    let (good_key, good_cert) = endpoint(1);
    // A certificate that lapses almost immediately.
    let short_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[9u8; 32]);
    let short_cert =
        self_signed_endpoint(&short_key, "axon-endpoint", Duration::from_secs(1)).unwrap();
    // Let it expire. Every pin below is CORRECT — only the clock rejects it.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // (a) Expired SERVER certificate → the client's verifier refuses.
    {
        let server = server_config(&short_key, &short_cert, &good_cert.fingerprint).unwrap();
        let client = client_config(&good_key, &good_cert, &short_cert.fingerprint).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let srv = tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });
        let connector = TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        assert!(
            connector.connect(name, tcp).await.is_err(),
            "client must reject an expired server certificate it otherwise pins"
        );
        srv.await.ok();
    }

    // (b) Expired CLIENT certificate → the server's verifier refuses.
    {
        let server = server_config(&good_key, &good_cert, &short_cert.fingerprint).unwrap();
        let client = client_config(&short_key, &short_cert, &good_cert.fingerprint).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.is_err()
        });
        let connector = TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        // The client may or may not observe the alert before its connect resolves;
        // the authoritative check is that the SERVER refused the handshake.
        let _ = connector.connect(name, tcp).await;
        assert!(
            srv.await.unwrap(),
            "server must reject an expired client certificate it otherwise pins"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_pin_fails_closed() {
    let (a_key, a_cert) = endpoint(1); // real server
    let (b_key, b_cert) = endpoint(2); // client
    let (_c_key, c_cert) = endpoint(3); // an identity the client wrongly expects

    let server = server_config(&a_key, &a_cert, &b_cert.fingerprint).unwrap();
    // The client pins C, but it is really talking to A — must reject.
    let client = client_config(&b_key, &b_cert, &c_cert.fingerprint).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let srv = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await; // expected to fail
        }
    });

    let connector = TlsConnector::from(Arc::new(client));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let result = connector.connect(name, tcp).await;
    assert!(
        result.is_err(),
        "client must reject a server it did not pin"
    );

    srv.await.ok();
}
