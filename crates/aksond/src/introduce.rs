//! First contact over identity tokens (design §8.2 step 4, ADR-0015): the
//! responder half served on the receive listener, and the dialer half that
//! runs on the first connection toward an imported peer.
//!
//! The disclosure order is the point. The dialer's hello carries only
//! thumbprints and a nonce; the responder answers with its own proof *first*
//! (the dialer can already check it against the imported root), and only then
//! does the dialer disclose its material — so a hijacked endpoint or a MITM
//! without the root key harvests nothing. Unknown callers are refused
//! generically before any signature work, and land in the knock log.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use akson_crypto::cert::EndpointCert;
use akson_crypto::identity::{Fingerprint, PeerIdentity};
use akson_crypto::keypair::PurposeKey;
use akson_crypto::purpose::KeyPurpose;
use akson_pairing::introduction::{
    build_intro_material, verify_introduction, Hello, IntroAck, IntroMaterial, IntroTranscript,
    Role, COMPLETE_PATH, HELLO_PATH, INTRODUCTION_MEDIA_TYPE, PROTOCOL_VERSION, TOKEN_VERSION,
};
use akson_pairing::session::peer_identity_from;
use akson_proto::profile::ProfileConfig;
use akson_proto::v1::AgentCard;
use akson_store::{IntroCommitOutcome, PeerImport, Store, StoredPeer};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::CONTENT_TYPE;
use hyper::Request;
use hyper_util::rt::TokioIo;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::bootstrap::DaemonState;
use crate::control::Problem;

/// The key-binding validity window this endpoint advertises (matches
/// `bootstrap_material`; real windows come with rotation work, §8.4).
const NOT_BEFORE: &str = "2020-01-01T00:00:00Z";
const NOT_AFTER: &str = "2035-01-01T00:00:00Z";

/// One endpoint's introduction identity: what it proves about itself (either
/// role) and what it verifies about the counterparty. Assembled once from
/// [`DaemonState`]; the e2e harness builds it from parts.
pub struct IntroIdentity {
    /// Statement keys, keyed by purpose (must include agent-card).
    pub keys: BTreeMap<KeyPurpose, PurposeKey>,
    /// The signed, profile-valid extended Agent Card.
    pub signed_card: AgentCard,
    /// The TLS key and certificate this side presents on the wire.
    pub tls_key: PurposeKey,
    pub cert: EndpointCert,
    /// RFC 7638 thumbprint of the agent-card (root) key.
    pub own_root: String,
    pub issuer: String,
    pub agent: String,
    /// The card bar the counterparty must pass.
    pub profile: ProfileConfig,
}

impl IntroIdentity {
    pub fn from_state(state: &DaemonState) -> Result<Self, Problem> {
        let keys = crate::pairing::statement_keys(state);
        let signed_card = crate::pairing::signed_endpoint_card(state)?;
        let own_root = state
            .identity()
            .purpose_key(KeyPurpose::AgentCard)
            .verifying()
            .to_jwk()
            .thumbprint();
        let local = &state.config().local_performer;
        let profile = intro_profile();
        Ok(Self {
            keys,
            signed_card,
            tls_key: state.identity().purpose_key(KeyPurpose::TlsEndpoint),
            cert: state.endpoint_cert().clone(),
            own_root,
            issuer: local.issuer.clone(),
            agent: local.agent.clone(),
            profile,
        })
    }
}

/// The profile every introduced card must pass: the full required Akson
/// extension set (design §10.1). A fixed, valid set cannot fail to build.
pub fn intro_profile() -> ProfileConfig {
    let uris = akson_ext::namespace::required_extension_uris();
    ProfileConfig::new(uris.into_iter().collect()).unwrap_or_else(|_| {
        unreachable!("the required extension set is non-empty by construction")
    })
}

/// The transcript for `role`'s proofs on this session. `key_binding_sha256`
/// stays empty — build/verify bind the presented record themselves.
fn transcript(
    role: Role,
    dialer_root: &str,
    responder_root: &str,
    dialer_tls_sha256: &str,
    responder_tls_sha256: &str,
    exporter: &[u8; 32],
    nonce: &str,
) -> IntroTranscript {
    IntroTranscript {
        protocol_version: PROTOCOL_VERSION,
        token_version: TOKEN_VERSION,
        role,
        dialer_root: dialer_root.to_owned(),
        responder_root: responder_root.to_owned(),
        dialer_tls_sha256: dialer_tls_sha256.to_owned(),
        responder_tls_sha256: responder_tls_sha256.to_owned(),
        tls_exporter: URL_SAFE_NO_PAD.encode(exporter),
        nonce: nonce.to_owned(),
        key_binding_sha256: String::new(),
    }
}

/// The verified counterparty's verification keys as the store retains them.
fn binding_keys(
    bindings: &akson_pairing::key_binding::KeyBindingSet,
) -> Vec<(String, [u8; 32])> {
    bindings
        .keys
        .iter()
        .filter_map(|(purpose, entry)| {
            let key = entry.jwk.to_key().ok()?;
            Some((purpose.clone(), key.to_bytes()))
        })
        .collect()
}

// ---------------------------------------------------------------- responder

/// Per-connection introduction state: the hello this TLS session presented.
/// One hello, one complete — RFC 9266's one-instance rule (ADR-0015).
pub type PendingIntro = Mutex<Option<Hello>>;

/// The single generic refusal for every pre-verification failure: one type,
/// one shape, no distinguishing detail (ADR-0015).
fn refused() -> (u16, String, Vec<u8>) {
    let p = Problem {
        type_: "urn:akson:error:introduction-refused".to_owned(),
        title: "the introduction was refused".to_owned(),
        status: 403,
        detail: None,
    };
    (
        403,
        "application/problem+json".to_owned(),
        serde_json::to_vec(&p).unwrap_or_default(),
    )
}

fn problem(status: u16, kind: &str, title: &str) -> (u16, String, Vec<u8>) {
    let p = Problem {
        type_: format!("urn:akson:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    };
    (
        status,
        "application/problem+json".to_owned(),
        serde_json::to_vec(&p).unwrap_or_default(),
    )
}

/// Handles one introduction request on the receive listener (the caller has
/// already routed by path, capped the body, rate-limited the source, and
/// locked the store). `source` feeds the knock log only.
#[allow(clippy::too_many_arguments)]
pub fn respond_introduction(
    me: &IntroIdentity,
    store: &Store,
    pending: &PendingIntro,
    path: &str,
    source: &str,
    dialer_tls_sha256: Option<&str>,
    exporter: Option<&[u8; 32]>,
    body: &[u8],
    now_unix: i64,
) -> (u16, String, Vec<u8>) {
    // Both flights need the session facts; without them nothing verifies.
    let (Some(dialer_tls), Some(exporter)) = (dialer_tls_sha256, exporter) else {
        return refused();
    };
    let Ok(mut pending) = pending.lock() else {
        return problem(500, "internal", "the request could not be processed");
    };

    if path == HELLO_PATH {
        // One authentication instance per connection (RFC 9266 §4.1).
        if pending.is_some() {
            return refused();
        }
        let Ok(hello) = serde_json::from_slice::<Hello>(body) else {
            return refused();
        };
        if hello.protocol_version != PROTOCOL_VERSION || hello.token_version != TOKEN_VERSION {
            let _ = store.record_knock(&hello.claimed_root, source, "bad-version", now_unix);
            return refused();
        }
        if hello.target_root != me.own_root {
            let _ = store.record_knock(&hello.claimed_root, source, "wrong-target", now_unix);
            return refused();
        }
        // THE admission gate: a table lookup, before any signature work.
        match store.peer_import(&hello.claimed_root) {
            Ok(Some(_)) => {}
            _ => {
                let _ = store.record_knock(&hello.claimed_root, source, "not-imported", now_unix);
                return refused();
            }
        }
        // Admitted: the responder proves FIRST (the dialer can already check
        // this against its import; nothing about the dialer is known yet
        // beyond an unauthenticated claim).
        let t = transcript(
            Role::Responder,
            &hello.claimed_root,
            &me.own_root,
            dialer_tls,
            &me.cert.fingerprint.value,
            exporter,
            &hello.nonce,
        );
        let Ok(material) = build_intro_material(
            &t,
            &me.issuer,
            &me.agent,
            &me.signed_card,
            &me.keys,
            NOT_BEFORE,
            NOT_AFTER,
            0,
        ) else {
            return problem(500, "internal", "the request could not be processed");
        };
        *pending = Some(hello);
        let Ok(body) = serde_json::to_vec(&material) else {
            return problem(500, "internal", "the request could not be processed");
        };
        return (200, INTRODUCTION_MEDIA_TYPE.to_owned(), body);
    }

    if path == COMPLETE_PATH {
        // A complete consumes the hello: a second one is a fresh refusal.
        let Some(hello) = pending.take() else {
            return refused();
        };
        let Ok(material) = serde_json::from_slice::<IntroMaterial>(body) else {
            return refused();
        };
        // Re-read the import inside the same store lock: the commit CAS runs
        // against the epoch as of NOW, so a removal since the hello refuses.
        let import = match store.peer_import(&hello.claimed_root) {
            Ok(Some(i)) => i,
            _ => {
                let _ = store.record_knock(&hello.claimed_root, source, "not-imported", now_unix);
                return refused();
            }
        };
        let t = transcript(
            Role::Dialer,
            &hello.claimed_root,
            &me.own_root,
            dialer_tls,
            &me.cert.fingerprint.value,
            exporter,
            &hello.nonce,
        );
        let now = OffsetDateTime::from_unix_timestamp(now_unix).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let verified = match verify_introduction(
            &hello.claimed_root,
            &t,
            dialer_tls,
            &material,
            &me.profile,
            now,
        ) {
            Ok(v) => v,
            Err(_) => {
                let _ = store.record_knock(&hello.claimed_root, source, "bad-proof", now_unix);
                return refused();
            }
        };
        let Ok(identity) = peer_identity_from(&verified.bindings, &material.extended_card) else {
            return refused();
        };
        let peer = StoredPeer {
            identity,
            local_note: String::new(),
        };
        let keys = binding_keys(&verified.bindings);
        match store.commit_introduced_peer(&hello.claimed_root, import.epoch, &peer, &keys, now_unix)
        {
            Ok(IntroCommitOutcome::Committed) | Ok(IntroCommitOutcome::AlreadyActive) => {
                let Ok(body) = serde_json::to_vec(&IntroAck { ok: true }) else {
                    return problem(500, "internal", "the request could not be processed");
                };
                (200, INTRODUCTION_MEDIA_TYPE.to_owned(), body)
            }
            // Post-proof, the parties are mutually authenticated — specific
            // problems are allowed (ADR-0015).
            Ok(IntroCommitOutcome::Suspended(_)) => problem(
                409,
                "peer-suspended",
                "pinned identity material changed; operator review required",
            ),
            Ok(IntroCommitOutcome::NameCollision) => problem(
                409,
                "name-collision",
                "a different identity already holds this agent name here",
            ),
            Ok(IntroCommitOutcome::EpochChanged) | Ok(IntroCommitOutcome::NotImported) => refused(),
            Err(_) => problem(500, "internal", "the request could not be processed"),
        }
    } else {
        refused()
    }
}

// ------------------------------------------------------------------- dialer

#[derive(Debug, thiserror::Error)]
pub enum IntroduceError {
    #[error("the import carries no endpoint hint — re-share it and `peer add --update`")]
    NoEndpoint,
    #[error("the endpoint hint is not host:port")]
    BadEndpoint,
    #[error(transparent)]
    Tls(#[from] akson_transport::tls::TlsError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    /// The responder's single generic refusal. The truthful rendering is a
    /// likely-causes list — not-imported-yet first — never one asserted cause.
    #[error(
        "the peer refused the introduction. Likely causes: they have not run \
         `akson peer add <your token>` yet; a version mismatch; or rate limiting"
    )]
    Refused,
    #[error("introduction failed with status {0}")]
    Status(u16),
    #[error("the peer's proof failed verification: {0}")]
    Verify(String),
    #[error("committing the peer failed: {0}")]
    Store(String),
    /// The handshake verified but the local CAS refused (epoch moved, name
    /// collision, or suspension) — the outcome says which.
    #[error("the introduction could not be committed: {0:?}")]
    NotCommitted(IntroCommitOutcome),
}

/// Dials `import`'s endpoint hint and runs the introduction (ADR-0015):
/// hello → verify the responder against the imported root → disclose and
/// prove → ack → commit under (root, epoch). The connection is dropped after
/// the ack; the first task runs on a fresh, pinned connection.
pub async fn dial_introduction(
    me: &IntroIdentity,
    store: Arc<Mutex<Store>>,
    import: &PeerImport,
    now: OffsetDateTime,
) -> Result<(PeerIdentity, IntroCommitOutcome), IntroduceError> {
    if import.endpoint_hint.is_empty() {
        return Err(IntroduceError::NoEndpoint);
    }
    let (host, port) = import
        .endpoint_hint
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h.to_owned(), p)))
        .ok_or(IntroduceError::BadEndpoint)?;

    let config = akson_transport::tls::introduction_client_config(&me.tls_key, &me.cert)?;
    let connector = TlsConnector::from(Arc::new(config));
    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .next()
        .ok_or(IntroduceError::BadEndpoint)?;
    let tcp = TcpStream::connect(addr).await?;
    let server_name =
        ServerName::try_from(host.clone()).map_err(|_| IntroduceError::BadEndpoint)?;
    let tls = connector.connect(server_name, tcp).await?;

    // The session facts every proof binds: the provisionally accepted server
    // certificate and this connection's RFC 9266 exporter.
    let conn = tls.get_ref().1;
    let responder_tls = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| Fingerprint::cert_sha256(c.as_ref()).value)
        .ok_or_else(|| IntroduceError::Http("no server certificate".into()))?;
    let exporter = akson_transport::tls::channel_binding(conn)
        .ok_or_else(|| IntroduceError::Http("no channel binding".into()))?;

    let mut nonce_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

    let hello = Hello {
        protocol_version: PROTOCOL_VERSION,
        token_version: TOKEN_VERSION,
        target_root: import.root_thumbprint.clone(),
        claimed_root: me.own_root.clone(),
        nonce: nonce.clone(),
    };

    // One hyper sender for both flights — the exporter identifies THIS
    // connection, so both requests must ride it.
    let (mut sender, conn_task) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| IntroduceError::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn_task.await;
    });

    // Flight 1 → 2: hello out, the responder's proof back.
    let body = post(
        &mut sender,
        HELLO_PATH,
        serde_json::to_vec(&hello).map_err(|e| IntroduceError::Http(e.to_string()))?,
    )
    .await?;
    let their_material: IntroMaterial =
        serde_json::from_slice(&body).map_err(|_| IntroduceError::Verify("malformed".into()))?;

    // Verify the responder against OUR import — before disclosing anything.
    let their_transcript = transcript(
        Role::Responder,
        &me.own_root,
        &import.root_thumbprint,
        &me.cert.fingerprint.value,
        &responder_tls,
        &exporter,
        &nonce,
    );
    let verified = verify_introduction(
        &import.root_thumbprint,
        &their_transcript,
        &responder_tls,
        &their_material,
        &me.profile,
        now,
    )
    .map_err(|e| IntroduceError::Verify(e.to_string()))?;

    // Flight 3 → 4: disclose, prove, and expect the ack.
    let my_transcript = transcript(
        Role::Dialer,
        &me.own_root,
        &import.root_thumbprint,
        &me.cert.fingerprint.value,
        &responder_tls,
        &exporter,
        &nonce,
    );
    let my_material = build_intro_material(
        &my_transcript,
        &me.issuer,
        &me.agent,
        &me.signed_card,
        &me.keys,
        NOT_BEFORE,
        NOT_AFTER,
        0,
    )
    .map_err(|e| IntroduceError::Http(e.to_string()))?;
    let ack_body = post(
        &mut sender,
        COMPLETE_PATH,
        serde_json::to_vec(&my_material).map_err(|e| IntroduceError::Http(e.to_string()))?,
    )
    .await?;
    let _ack: IntroAck =
        serde_json::from_slice(&ack_body).map_err(|_| IntroduceError::Verify("bad ack".into()))?;

    // Commit under the epoch this dial started from; a racing removal refuses.
    let identity = peer_identity_from(&verified.bindings, &their_material.extended_card)
        .map_err(|e| IntroduceError::Verify(e.to_string()))?;
    let keys = binding_keys(&verified.bindings);
    let peer = StoredPeer {
        identity: identity.clone(),
        local_note: String::new(),
    };
    let outcome = {
        let store = store.lock().map_err(|_| IntroduceError::Store("poisoned".into()))?;
        store
            .commit_introduced_peer(
                &import.root_thumbprint,
                import.epoch,
                &peer,
                &keys,
                now.unix_timestamp(),
            )
            .map_err(|e| IntroduceError::Store(e.to_string()))?
    };
    match outcome {
        IntroCommitOutcome::Committed | IntroCommitOutcome::AlreadyActive => {
            Ok((identity, outcome))
        }
        other => Err(IntroduceError::NotCommitted(other)),
    }
}

/// One POST on the shared sender; 403 renders as the likely-causes refusal.
async fn post(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    path: &str,
    body: Vec<u8>,
) -> Result<Bytes, IntroduceError> {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(CONTENT_TYPE, INTRODUCTION_MEDIA_TYPE)
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| IntroduceError::Http(e.to_string()))?;
    let resp = sender
        .send_request(request)
        .await
        .map_err(|e| IntroduceError::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    if status == 403 {
        return Err(IntroduceError::Refused);
    }
    if status != 200 {
        return Err(IntroduceError::Status(status));
    }
    let collected = Limited::new(
        resp.into_body(),
        akson_pairing::introduction::MAX_INTRODUCTION_BODY,
    )
    .collect()
    .await
    .map_err(|_| IntroduceError::Http("response too large".into()))?;
    Ok(collected.to_bytes())
}
