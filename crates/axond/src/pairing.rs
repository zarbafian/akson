//! Pairing over the control surface (design §8.2): the accepter side.
//!
//! [`run_pair_accept`] connects to an inviter's bootstrap endpoint pinned to the
//! invitation's certificate, presents this endpoint's material — its signed Agent
//! Card and its paired-purpose verification keys — verifies the inviter's
//! equivalent response, and pins it as a peer. After that the two endpoints hold
//! each other's verified identity and can exchange tasks.

use std::collections::BTreeMap;

use axon_crypto::purpose::KeyPurpose;
use axon_pairing::handler::BootstrapMaterial;
use axon_pairing::invitation::Invitation;
use axon_proto::card_sig;
use axon_proto::v1::AgentCard;
use axon_transport::client::accept_invitation;
use time::OffsetDateTime;

use crate::bootstrap::DaemonState;
use crate::control::Problem;

/// Builds this endpoint's pairing material from its identity (design §8.2 step 5):
/// a signed Agent Card plus its paired-purpose verification keys, so the peer can
/// verify everything this endpoint later signs — proposals, decisions, results,
/// evidence, outcomes.
pub(crate) fn bootstrap_material(state: &DaemonState) -> Result<BootstrapMaterial, Problem> {
    let identity = state.identity();
    let local = &state.config().local_performer;

    let card_value = serde_json::json!({
        "name": local.agent,
        "description": "axon endpoint",
        "version": "1.0.0",
        "supportedInterfaces": [{
            "url": state.config().interface_url,
            "protocolBinding": "HTTP+JSON",
            "protocolVersion": "1.0",
        }],
        "capabilities": { "streaming": false, "pushNotifications": false },
    });
    let mut card: AgentCard = serde_json::from_value(card_value)
        .map_err(|_| problem(500, "internal", "the agent card could not be built"))?;
    let sig = card_sig::sign_card(&card, &identity.purpose_key(KeyPurpose::AgentCard))
        .map_err(|_| problem(500, "card-sign", "the agent card could not be signed"))?;
    card.signatures.push(sig);

    // The key-binding carries only the STATEMENT verification keys (a closed set);
    // TLS identity is pinned by the certificate digest, not advertised here.
    let mut keys = BTreeMap::new();
    for purpose in KeyPurpose::PAIRED {
        if purpose == KeyPurpose::TlsEndpoint {
            continue;
        }
        keys.insert(purpose, identity.purpose_key(purpose));
    }
    Ok(BootstrapMaterial {
        tls_sha256: state.endpoint_cert().fingerprint.value.clone(),
        subject_issuer: local.issuer.clone(),
        subject_agent: local.agent.clone(),
        signed_card: card,
        keys,
        not_before: "2020-01-01T00:00:00Z".to_owned(),
        not_after: "2035-01-01T00:00:00Z".to_owned(),
        generation: 0,
    })
}

/// Accepts a pairing invitation (design §8.2 steps 3–7). Blocks on its own runtime,
/// so it composes with the synchronous control socket. The store lock is held for
/// the exchange (pairing is operator-initiated and brief).
pub fn run_pair_accept(
    state: &DaemonState,
    invitation_json: &str,
) -> Result<serde_json::Value, Problem> {
    let invitation: Invitation = serde_json::from_str(invitation_json)
        .map_err(|_| problem(400, "bad-invitation", "the invitation is malformed"))?;
    let material = bootstrap_material(state)?;
    let tls_key = state.identity().purpose_key(KeyPurpose::TlsEndpoint);
    let cert = state.endpoint_cert();
    let now = OffsetDateTime::now_utc();
    let store_arc = state.store();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| internal())?;
    // The store lock is held across the pairing exchange. accept_invitation needs
    // `&mut store` for the whole flow (it interleaves the network POST with the
    // durable peer write), and this runs on a runtime dedicated to this one call,
    // so nothing else contends for the executor — the held-lock lint is a
    // false positive here.
    #[allow(clippy::await_holding_lock)]
    let peer = runtime
        .block_on(async {
            let mut store = store_arc
                .lock()
                .map_err(|_| "the store is poisoned".to_owned())?;
            accept_invitation(&invitation, &tls_key, cert, &material, &mut *store, now)
                .await
                .map_err(|e| e.to_string())
        })
        .map_err(|e| problem_detail(502, "pair-failed", "pairing failed", e))?;

    Ok(serde_json::json!({
        "paired": true,
        "peer": peer.agent_id,
        "issuer": peer.issuer,
        "endpoint": peer.endpoint_id,
    }))
}

fn internal() -> Problem {
    problem(500, "internal", "the request could not be processed")
}

fn problem(status: u16, kind: &str, title: &str) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: None,
    }
}

fn problem_detail(status: u16, kind: &str, title: &str, e: impl std::fmt::Display) -> Problem {
    Problem {
        type_: format!("urn:axon:error:{kind}"),
        title: title.to_owned(),
        status,
        detail: Some(e.to_string()),
    }
}
