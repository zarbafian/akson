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
//! - `coord-dispatch --state <db> --seed <n> --token <token-file>
//!    [--label <l>] [--agent NAME] --payload <text>`
//!   Introduces (as above), then runs the real coordination surface end to end
//!   over the introduced relationship: `stage` on coord, `stage consent` on
//!   admin, `dispatch` — which carries the staged bytes to the peer in a
//!   coordination envelope over pinned mutual TLS (ADR-0016 §2). Prints
//!   `DISPATCHED <state> …` and exits 0 only when the peer acknowledged.

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use akson_contract::Identity;
use akson_crypto::cert::self_signed_endpoint;
use akson_crypto::keypair::PurposeVerifyingKey;
use akson_crypto::purpose::KeyPurpose;
use akson_crypto::token::{decode_token, encode_token, split_presentation};
use akson_proto::card_sig;
use akson_proto::v1::AgentCard;
use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, Store};
use akson_transport::tls::bootstrap_server_config;
use aksond::{
    dial_introduction, intro_profile, serve_receive, ControlRequest, DaemonConfig, DaemonState,
    IdentityKeys, IntroIdentity, ReceiveState, StorePeerResolver,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
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

/// This seed's key material, derived exactly as the live daemon derives its own:
/// ONE master seed, every purpose key a domain-separated derivation from it
/// (`IdentityKeys`). That matters beyond tidiness — `DaemonState::from_parts`
/// computes an endpoint's root from its `agent-card` key, so a harness endpoint
/// that derived its keys any other way would introduce under one root and
/// dispatch under another.
fn identity_keys(seed: u8) -> IdentityKeys {
    IdentityKeys::from_master([seed; 32])
}

/// One endpoint's introduction identity, deterministic from `seed`: statement
/// keys, a profile-valid signed card, and its TLS material — the same shape
/// `IntroIdentity::from_state` assembles in the live daemon.
fn identity(agent: &str, seed: u8, interface_url: &str) -> Result<IntroIdentity, Err> {
    let master = identity_keys(seed);
    let mut keys = BTreeMap::new();
    for purpose in KeyPurpose::PAIRED {
        if purpose == KeyPurpose::TlsEndpoint {
            continue;
        }
        keys.insert(purpose, master.purpose_key(purpose));
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
            // The card's interface URL is what an introduction pins as the
            // peer's `endpoint_id`, and therefore what a coordination dispatch
            // later routes to. A placeholder here would introduce fine and then
            // be unroutable, so it carries the endpoint's real address.
            "url": interface_url,
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

    let tls_key = master.purpose_key(KeyPurpose::TlsEndpoint);
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
    let root = identity_keys(seed)
        .purpose_key(KeyPurpose::AgentCard)
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
    match store.add_peer_import(&thumb, label, hint.unwrap_or(""), now)? {
        akson_store::ImportOutcome::Added => Ok(thumb),
        // Reused state must fail loudly, not introduce whichever prior import
        // owns the label (slice-3 review).
        other => Err(format!("import of {label:?} not applied: {other:?}").into()),
    }
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

    // Bind first so the written token — and the signed card's interface URL,
    // which is what the peer pins as this endpoint's address — carry the real,
    // reachable port.
    let listener = TcpListener::bind((host.as_str(), port)).await?;
    let bound = listener.local_addr()?;
    let interface_url = format!("https://{advertise}:{}/a2a", bound.port());
    let me = identity(&agent, seed, &interface_url)?;
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
                root: me.own_root.clone(),
            },
            std::collections::BTreeSet::new(),
            interface_url,
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

/// Imports the peer token and dials the introduction as `me`, leaving the
/// relationship pinned on both sides. Returns the peer's label.
///
/// `me` is passed in rather than derived here, and that is load-bearing: a
/// self-signed endpoint certificate embeds timestamps, so building the identity
/// twice in one process yields two different fingerprints — the peer would pin
/// one and then refuse the other at the next connection.
async fn introduce(args: &Args, me: &IntroIdentity, seed: u8) -> Result<String, Err> {
    let store = Arc::new(Mutex::new(Store::open(
        args.require("--state")?.as_ref(),
        &Kek::from_bytes([seed; 32]),
        checkpoint(),
    )?));

    let label = args.get("--label").unwrap_or("peer").to_owned();
    {
        let guard = store.lock().map_err(|_| "store poisoned")?;
        import_token_file(&guard, args.require("--token")?, &label)?;
    }
    let import = store
        .lock()
        .map_err(|_| "store poisoned")?
        .peer_import_by_label(&label)?
        .ok_or("the import vanished")?;

    let now = time::OffsetDateTime::now_utc();
    let (peer, outcome) = dial_introduction(me, store, &import, now).await?;
    println!("INTRODUCED with {} ({outcome:?})", peer.agent_id);
    Ok(label)
}

async fn run_introduce(args: Args) -> Result<(), Err> {
    let seed = args.seed()?;
    let agent = args.get("--agent").unwrap_or("dialer").to_owned();
    let advertise = args.get("--advertise").unwrap_or("dialer.invalid");
    let me = identity(&agent, seed, &format!("https://{advertise}/a2a"))?;
    introduce(&args, &me, seed).await?;
    Ok(())
}

/// The coordination surface end to end across two processes (ADR-0016 §2):
/// introduce, `stage` on coord, `stage consent` on admin, then `dispatch` —
/// which builds the coordination envelope and carries the staged bytes to the
/// introduced peer over pinned mutual TLS.
///
/// Every step runs the **real** `DaemonState::dispatch`, over the very store the
/// introduction just committed to, with the same endpoint certificate the peer
/// pinned. Nothing about the carriage is simulated; the only thing the harness
/// supplies is the operator's consent, on the admin surface where it belongs.
async fn run_coord_dispatch(args: Args) -> Result<(), Err> {
    let seed = args.seed()?;
    let agent = args.get("--agent").unwrap_or("dialer").to_owned();
    let payload = args
        .get("--payload")
        .unwrap_or("coordination payload")
        .to_owned();
    let advertise = args
        .get("--advertise")
        .unwrap_or("dialer.invalid")
        .to_owned();
    // ONE identity for the whole process: the certificate the peer pins during
    // the introduction is the certificate the dispatch then presents.
    let me = identity(&agent, seed, &format!("https://{advertise}/a2a"))?;
    let label = introduce(&args, &me, seed).await?;

    // Re-open the store the introduction committed to (the dial's handle is
    // gone), and build the daemon state over it with that same identity.
    let store = Store::open(
        args.require("--state")?.as_ref(),
        &Kek::from_bytes([seed; 32]),
        checkpoint(),
    )?;
    let config = DaemonConfig {
        data_dir: std::path::PathBuf::from("/nonexistent-harness-data-dir"),
        local_performer: Identity {
            issuer: "local".to_owned(),
            agent: agent.clone(),
            root: me.own_root.clone(),
        },
        interface_url: format!("https://{advertise}/a2a"),
        receive_addr: None,
        worker_command: None,
        worker_exec: None,
        on_task: None,
    };
    let state = DaemonState::from_parts(store, identity_keys(seed), me.cert.clone(), config);

    // `dispatch` owns its own runtime for the outbound POST (exactly as the
    // daemon's blocking control sockets call it), so it must not run on this
    // async worker.
    tokio::task::spawn_blocking(move || coord_steps(&state, &label, &payload))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| -> Err { e.into() })
}

/// stage → consent → dispatch → replay-refused, on the surfaces that own each
/// step. Blocking, because `dispatch` drives the outbound carriage itself.
fn coord_steps(state: &DaemonState, label: &str, payload: &str) -> Result<(), String> {
    // `Problem` is an RFC 9457 body, not a std error; carry it as text (which is
    // also what makes this closure's error `Send`, so it can cross back off the
    // blocking pool).
    let call = |req| {
        state.dispatch(&req).map_err(|p: aksond::Problem| {
            format!("{}: {} {}", p.status, p.type_, p.detail.unwrap_or(p.title))
        })
    };

    // 1. stage — inert, on the coordination surface.
    let staged = call(ControlRequest::Stage {
        task_type: "https://byom.example/task/exchange/v1".to_owned(),
        performer: label.to_owned(),
        payload_base64: STANDARD.encode(payload),
    })?;
    let stage_ref = staged["stage_ref"]
        .as_str()
        .ok_or_else(|| "stage returned no reference".to_owned())?
        .to_owned();
    println!("STAGED {stage_ref} (digest {})", staged["staged_digest"]);

    // 2. consent — the operator's one-shot yes, on ADMIN. A coordination
    //    connection cannot reach this op at all; the harness stands in for the
    //    human who read the risk card.
    let consent = call(ControlRequest::StageConsent {
        stage_ref: stage_ref.clone(),
    })?;
    let receipt = consent["consent_receipt"]
        .as_str()
        .ok_or_else(|| "consent returned no receipt".to_owned())?
        .to_owned();
    println!("CONSENTED {receipt}");

    // 3. dispatch — spend the receipt, commit, and carry the bytes.
    let dispatched = call(ControlRequest::Dispatch {
        stage_ref: stage_ref.clone(),
        consent_receipt: receipt.clone(),
        execution_key: "exec-interop-1".to_owned(),
    })?;
    let egress = dispatched["egress"]["state"].as_str().unwrap_or("");
    println!(
        "DISPATCHED {egress} receipt={} detail={}",
        dispatched["dispatch_receipt"], dispatched["egress"]["detail"]
    );
    if egress != "sent" {
        return Err(format!(
            "the coordination payload did not reach the peer: {egress}"
        ));
    }

    // The one-shot property, across a real relationship: a DIFFERENT execution
    // key on the spent receipt must be refused.
    match state.dispatch(&ControlRequest::Dispatch {
        stage_ref,
        consent_receipt: receipt,
        execution_key: "exec-interop-2".to_owned(),
    }) {
        Err(p) if p.status == 409 => println!("REPLAY REFUSED {}", p.type_),
        Err(p) => return Err(format!("unexpected refusal {p:?}")),
        Ok(_) => return Err("a spent consent receipt dispatched twice".to_owned()),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Err> {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        return Err(
            "usage: akson-harness <token|serve|introduce|coord-dispatch> [--flag value]...".into(),
        );
    }
    let cmd = argv.remove(0);
    let args = Args(argv);
    match cmd.as_str() {
        "token" => run_token(args),
        "serve" => run_serve(args).await,
        "introduce" => run_introduce(args).await,
        "coord-dispatch" => run_coord_dispatch(args).await,
        other => Err(format!(
            "unknown subcommand {other:?}; expected token|serve|introduce|coord-dispatch"
        )
        .into()),
    }
}
