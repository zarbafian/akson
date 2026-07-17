//! Interop test-harness runner: a minimal runnable Axon endpoint that exercises
//! the real crates over real sockets, for multi-endpoint scenarios.
//!
//! This is **not** the daemon (that is M12); it is a thin wiring of the shipped
//! crates so scenarios can run two (or more) endpoints as separate processes or
//! containers. Keys and the store KEK are derived deterministically from a
//! `--seed`, so it is for testing only, never production.
//!
//! Subcommands:
//! - `serve  --state <db> --seed <n> [--host H] [--advertise A] [--port P] --invitation-out <f> [--agent NAME]`
//!   Creates a self-signed endpoint cert, mints an invitation carrying the real
//!   endpoint URL, writes it (mode-0600) to `--invitation-out`, and serves the
//!   pairing bootstrap endpoint (design §8.2).
//! - `pair   --state <db> --seed <n> --invitation <f> [--agent NAME]`
//!   Reads the invitation and runs the accepter side end to end, pinning the
//!   inviter. Prints `PAIRED with <agent>` and exits 0 on success.

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use axon_crypto::cert::self_signed_endpoint;
use axon_crypto::keypair::PurposeKey;
use axon_crypto::purpose::KeyPurpose;
use axon_pairing::handler::BootstrapMaterial;
use axon_pairing::invitation::Invitation;
use axon_pairing::state_machine::PairingLedger;
use axon_pairing::transfer::{read_invitation_file, write_invitation_file};
use axon_proto::card_sig;
use axon_proto::v1::AgentCard;
use axon_store::envelope::Kek;
use axon_store::{ExternalCheckpoint, Store};
use axon_transport::bootstrap::{serve, BootstrapState};
use axon_transport::client::accept_invitation;
use axon_transport::tls::bootstrap_server_config;
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

/// Builds an endpoint's bootstrap material (a signed Agent Card + statement keys)
/// for `agent`, deterministically from `seed`.
fn material(tls_sha256: &str, agent: &str, seed: u8) -> Result<BootstrapMaterial, Err> {
    let card_key = PurposeKey::from_seed(KeyPurpose::AgentCard, &[seed; 32]);
    let card_json = format!(
        r#"{{"name":"{agent}","description":"harness endpoint","version":"1.0.0",
            "supportedInterfaces":[{{"url":"https://{agent}/x","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}}],
            "capabilities":{{"streaming":false,"pushNotifications":false}}}}"#
    );
    let mut card: AgentCard = serde_json::from_str(&card_json)?;
    card.signatures.push(card_sig::sign_card(&card, &card_key)?);

    let mut keys = BTreeMap::new();
    keys.insert(
        KeyPurpose::AgentCard,
        PurposeKey::from_seed(KeyPurpose::AgentCard, &[seed; 32]),
    );
    Ok(BootstrapMaterial {
        tls_sha256: tls_sha256.to_owned(),
        subject_issuer: "local".to_owned(),
        subject_agent: agent.to_owned(),
        signed_card: card,
        keys,
        not_before: "2020-01-01T00:00:00Z".to_owned(),
        not_after: "2030-01-01T00:00:00Z".to_owned(),
        generation: 0,
    })
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

async fn run_serve(args: Args) -> Result<(), Err> {
    let seed = args.seed()?;
    let agent = args.get("--agent").unwrap_or("inviter").to_owned();
    let host = args.get("--host").unwrap_or("127.0.0.1").to_owned();
    // The hostname put in the endpoint URL, if it differs from the bind address
    // (e.g. bind 0.0.0.0 in a container, advertise the service name).
    let advertise = args.get("--advertise").unwrap_or(host.as_str()).to_owned();
    let port: u16 = args.get("--port").unwrap_or("0").parse()?;

    let tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[seed; 32]);
    let cert = self_signed_endpoint(&tls_key, "endpoint", Duration::from_secs(86_400))?;
    let tls_sha256 = cert.fingerprint.value.clone();

    // Bind first so the invitation carries the real, reachable endpoint URL.
    let listener = TcpListener::bind((host.as_str(), port)).await?;
    let bound = listener.local_addr()?;
    let url = format!("https://{advertise}:{}/bootstrap", bound.port());

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (invitation, pending) = Invitation::create(
        url.clone(),
        tls_sha256.clone(),
        "kid".to_owned(),
        now,
        900,
        5,
    );
    let verifier = pending.verifier();

    let mut store = Store::open(
        args.require("--state")?.as_ref(),
        &Kek::from_bytes([seed; 32]),
        checkpoint(),
    )?;
    store.put_active(verifier, pending)?;
    write_invitation_file(args.require("--invitation-out")?, &invitation)?;

    let state = Arc::new(BootstrapState::new(
        store,
        material(&tls_sha256, &agent, seed)?,
    ));
    let acceptor = TlsAcceptor::from(Arc::new(bootstrap_server_config(&tls_key, &cert)?));
    println!("SERVING {url} (agent={agent}); invitation written");
    serve(listener, acceptor, state).await?;
    Ok(())
}

async fn run_pair(args: Args) -> Result<(), Err> {
    let seed = args.seed()?;
    let agent = args.get("--agent").unwrap_or("accepter").to_owned();

    let invitation: Invitation = read_invitation_file(args.require("--invitation")?)?;
    let tls_key = PurposeKey::from_seed(KeyPurpose::TlsEndpoint, &[seed; 32]);
    let cert = self_signed_endpoint(&tls_key, "endpoint", Duration::from_secs(86_400))?;
    let mut store = Store::open(
        args.require("--state")?.as_ref(),
        &Kek::from_bytes([seed; 32]),
        checkpoint(),
    )?;
    let accepter = material(&cert.fingerprint.value, &agent, seed)?;

    let now = time::OffsetDateTime::now_utc();
    let inviter =
        accept_invitation(&invitation, &tls_key, &cert, &accepter, &mut store, now).await?;
    println!("PAIRED with {}", inviter.agent_id);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Err> {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        return Err("usage: axon-harness <serve|pair> [--flag value]...".into());
    }
    let cmd = argv.remove(0);
    let args = Args(argv);
    match cmd.as_str() {
        "serve" => run_serve(args).await,
        "pair" => run_pair(args).await,
        other => Err(format!("unknown subcommand {other:?}; expected serve|pair").into()),
    }
}
