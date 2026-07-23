//! Interop test-harness runner: a minimal runnable Akson endpoint that exercises
//! the real crates over real sockets, for multi-endpoint scenarios.
//!
//! This is **not** the daemon; it is a thin wiring of the shipped crates so
//! scenarios can run two (or more) endpoints as separate processes or
//! containers. Keys and the store KEK are derived deterministically from a
//! `--seed`, so it is for testing only, never production.
//!
//! Subcommands (identity-token pairing, design §8.2 / ADR-0013/0015):
//! - `token --seed <n> [--advertise host:port] --token-out <f>`
//!   Writes this seed's identity token (presentation form) to a file — the
//!   out-of-band exchange, as a file drop.
//! - `serve --state <db> --seed <n> [--host H] [--advertise A] [--port P]
//!    --token-out <f> [--import <token-file> --label <l>] [--agent NAME]`
//!   Imports a peer's token (the operator's yes), writes its own token with
//!   the live port, and serves the receive listener with introductions.
//! - `introduce --state <db> --seed <n> --token <token-file> [--agent NAME]`
//!   Imports the token in the file and dials the introduction. Prints
//!   `INTRODUCED with <agent>` and exits 0 on success.

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use akson_contract::Identity;
use akson_crypto::cert::self_signed_endpoint;
use akson_crypto::keypair::{PurposeKey, PurposeVerifyingKey};
use akson_crypto::purpose::KeyPurpose;
use akson_crypto::token::{decode_token, encode_token, split_presentation};
use akson_proto::card_sig;
use akson_proto::v1::AgentCard;
use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, Store};
use akson_transport::tls::bootstrap_server_config;
use aksond::{
    dial_introduction, intro_profile, serve_receive, IntroIdentity, ReceiveState,
    StorePeerResolver,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

type Err = Box<dyn Error>;

/// The fixed external checkpoint for a harness store (test-only).
fn checkpoint() -> ExternalCheckpoint {
    ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    }
}

/// One endpoint's introduction identity, deterministic from `seed`: statement
/// keys, a profile-valid signed card, and its TLS material — the same shape
/// `IntroIdentity::from_state` assembles in the live daemon.
fn identity(agent: &str, seed: u8) -> Result<IntroIdentity, Err> {
    let mut keys = BTreeMap::new();
    for purpose in KeyPurpose::PAIRED {
        if purpose == KeyPurpose::TlsEndpoint {
            continue;
        }
        keys.insert(
            purpose,
            PurposeKey::from_seed(purpose, &[seed ^ (purpose as u8); 32]),
        );
    }
    let card_key = &keys[&KeyPurpose::AgentCard];
    let own_root = card_key.verifying().to_jwk().thumbprint();

    let extensions: Vec<serde_json::Value> = akson_ext::namespace::required_extension_uris()
        .into_iter()
        .map(|uri| serde_json::json!({ "uri": uri, "required": true }))
        .collect();
    let mut card: AgentCard = serde_json::from_value(serde_json::json!({
        "name": agent, "description": "harness endpoint", "version": "1.0.0",
        "supportedInterfaces": [{
            "url": format!("https://{agent}.invalid/a2a"),
            "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0",
        }],
        "capabilities": {
            "streaming": false, "pushNotifications": false,
            "extendedAgentCard": true, "extensions": extensions,
        },
        "securitySchemes": { "mtls": { "mtlsSecurityScheme": { "description": "pinned" } } },
        "securityRequirements": [{ "schemes": { "mtls": { "list": [] } } }],
    }))?;
    card.signatures.push(card_sig::sign_card(&card, card_key)?);

    let tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[seed; 32]);
    let cert = self_signed_endpoint(&tls_key, "endpoint", Duration::from_secs(86_400))?;
    Ok(IntroIdentity {
        keys,
        signed_card: card,
        tls_key,
        cert,
        own_root,
        issuer: "local".to_owned(),
        agent: agent.to_owned(),
        profile: intro_profile(),
    })
}

/// This seed's token in presentation form, with `hint` when given.
fn presentation(seed: u8, hint: Option<&str>) -> String {
    let root = PurposeKey::from_seed(
        KeyPurpose::AgentCard,
        &[seed ^ (KeyPurpose::AgentCard as u8); 32],
    )
    .verifying()
    .to_public_bytes();
    let token = encode_token(&root);
    match hint {
        Some(h) => format!("{token}@{h}"),
        None => token,
    }
}

/// Imports the token in `file` into `store` under `label`. The trust act.
fn import_token_file(store: &Store, file: &str, label: &str) -> Result<String, Err> {
    let text = std::fs::read_to_string(file)?;
    let (tok, hint) = split_presentation(text.trim());
    let decoded = decode_token(tok)?;
    let thumb = PurposeVerifyingKey::from_public_bytes(KeyPurpose::AgentCard, &decoded.root_key)
        .map_err(|e| format!("token key: {e}"))?
        .to_jwk()
        .thumbprint();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    store.add_peer_import(&thumb, label, hint.unwrap_or(""), now)?;
    Ok(thumb)
}

/// Reads `--flag value` pairs from the argument list.
struct Args(Vec<String>);
impl Args {
    fn get(&self, flag: &str) -> Option<&str> {
        self.0
            .iter()
            .position(|a| a == flag)
            .and_then(|i| self.0.get(i + 1))
            .map(String::as_str)
    }
    fn require(&self, flag: &str) -> Result<&str, Err> {
        self.get(flag)
            .ok_or_else(|| format!("missing required argument {flag}").into())
    }
    fn seed(&self) -> Result<u8, Err> {
        Ok(self.require("--seed")?.parse()?)
    }
}

fn run_token(args: Args) -> Result<(), Err> {
    let seed = args.seed()?;
    let line = presentation(seed, args.get("--advertise"));
    std::fs::write(args.require("--token-out")?, format!("{line}\n"))?;
    println!("TOKEN written");
    Ok(())
}

async fn run_serve(args: Args) -> Result<(), Err> {
    let seed = args.seed()?;
    let agent = args.get("--agent").unwrap_or("endpoint").to_owned();
    let host = args.get("--host").unwrap_or("127.0.0.1").to_owned();
    // The hostname put in the token's hint, if it differs from the bind
    // address (e.g. bind 0.0.0.0 in a container, advertise the service name).
    let advertise = args.get("--advertise").unwrap_or(host.as_str()).to_owned();
    let port: u16 = args.get("--port").unwrap_or("0").parse()?;

    let me = identity(&agent, seed)?;
    let store = Arc::new(Mutex::new(Store::open(
        args.require("--state")?.as_ref(),
        &Kek::from_bytes([seed; 32]),
        checkpoint(),
    )?));

    // The operator's yes: import the peer token before serving, so its
    // introduction is admitted the moment we listen.
    if let Some(peer_token) = args.get("--import") {
        let label = args.get("--label").unwrap_or("peer");
        let guard = store.lock().map_err(|_| "store poisoned")?;
        let thumb = import_token_file(&guard, peer_token, label)?;
        drop(guard);
        println!("IMPORTED {label} ({thumb})");
    }

    // Bind first so the written token carries the real, reachable port.
    let listener = TcpListener::bind((host.as_str(), port)).await?;
    let bound = listener.local_addr()?;
    let line = presentation(seed, Some(&format!("{advertise}:{}", bound.port())));
    std::fs::write(args.require("--token-out")?, format!("{line}\n"))?;

    let acceptor = TlsAcceptor::from(Arc::new(bootstrap_server_config(&me.tls_key, &me.cert)?));
    let state = Arc::new(
        ReceiveState::new(
            store,
            StorePeerResolver,
            Identity {
                issuer: "local".to_owned(),
                agent: agent.clone(),
            },
            std::collections::BTreeSet::new(),
            format!("https://{advertise}:{}/a2a", bound.port()),
        )
        .with_introduction(Arc::new(me)),
    );
    println!(
        "SERVING {advertise}:{} (agent={agent}); token written",
        bound.port()
    );
    serve_receive(listener, acceptor, state).await?;
    Ok(())
}

async fn run_introduce(args: Args) -> Result<(), Err> {
    let seed = args.seed()?;
    let agent = args.get("--agent").unwrap_or("dialer").to_owned();
    let me = identity(&agent, seed)?;
    let store = Arc::new(Mutex::new(Store::open(
        args.require("--state")?.as_ref(),
        &Kek::from_bytes([seed; 32]),
        checkpoint(),
    )?));

    let label = args.get("--label").unwrap_or("peer");
    {
        let guard = store.lock().map_err(|_| "store poisoned")?;
        import_token_file(&guard, args.require("--token")?, label)?;
    }
    let import = store
        .lock()
        .map_err(|_| "store poisoned")?
        .peer_import_by_label(label)?
        .ok_or("the import vanished")?;

    let now = time::OffsetDateTime::now_utc();
    let (peer, outcome) = dial_introduction(&me, store, &import, now).await?;
    println!("INTRODUCED with {} ({outcome:?})", peer.agent_id);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Err> {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        return Err("usage: akson-harness <token|serve|introduce> [--flag value]...".into());
    }
    let cmd = argv.remove(0);
    let args = Args(argv);
    match cmd.as_str() {
        "token" => run_token(args),
        "serve" => run_serve(args).await,
        "introduce" => run_introduce(args).await,
        other => {
            Err(format!("unknown subcommand {other:?}; expected token|serve|introduce").into())
        }
    }
}
