//! A2A request ingress — the v1 profile gates and idempotency decision every
//! authenticated request passes before any operation runs (design §9.1, §9.2,
//! §10.1). This is the pure logic; the axum HTTP layer is a thin adapter that
//! extracts [`Ingress`] from the request and acts on the [`Admit`] verdict.
//!
//! The order is fail-closed and matches the design: content type, then
//! `A2A-Version`, then Content-Digest (rejected "before Message parsing"), then
//! the required-extension set (missing/unsupported "fail before state lookup,
//! Task creation, or content processing"), and only then the idempotency peek.
//!
//! What you write:
//! ```no_run
//! # use akson_transport::ingress::{admit, Admit, Ingress};
//! # use std::collections::BTreeSet;
//! # fn go(store: &akson_store::Store, req: &Ingress) {
//! match admit(store, &BTreeSet::new(), req).unwrap() {
//!     Admit::Accept(covered) => { /* process, then store.receive_request(&covered, ..) */ }
//!     Admit::Duplicate { response, .. } => { /* return the saved bytes */ }
//!     Admit::Conflict => { /* security event; refuse */ }
//!     Admit::Rejected(reason) => { /* map to an HTTP status */ }
//! }
//! # }
//! ```

use std::collections::BTreeSet;

use akson_proto::{profile, A2A_MEDIA_TYPE, A2A_VERSION};
use akson_store::delivery::{body_digest, verify_content_digest, CoveredValues, DeliveryError};
use akson_store::{Receipt, Store, StoreError};

/// The parts the HTTP layer extracts from an authenticated (mTLS-pinned)
/// request. `peer` is the authenticated peer identity, not a claim in the body.
#[derive(Debug)]
pub struct Ingress<'a> {
    pub peer: &'a str,
    pub method: &'a str,
    pub content_type: &'a str,
    pub a2a_version: Option<&'a str>,
    pub content_digest: Option<&'a str>,
    pub activated_extensions: &'a [String],
    pub interface_url: &'a str,
    pub tenant: Option<&'a str>,
    pub message_id: &'a str,
    pub body: &'a [u8],
}

/// The ingress verdict.
#[derive(Debug)]
pub enum Admit {
    /// Passed every gate and first sight: process the operation, then commit
    /// durably with these covered values (design §9.2 durable-before-response).
    Accept(CoveredValues),
    /// Exact replay — return the saved response and server-assigned Task id.
    Duplicate {
        task_id: Option<String>,
        response: Vec<u8>,
    },
    /// Same peer + Message id with a covered value changed — a security event;
    /// never a second effect.
    Conflict,
    /// A gate failed before any processing.
    Rejected(Reject),
}

/// Why a request was rejected at ingress. Each maps to an HTTP status at the
/// edge (415, 400, or the A2A failed-precondition shape).
#[derive(Debug)]
pub enum Reject {
    /// Content type is not `application/a2a+json`.
    UnsupportedMediaType,
    /// `A2A-Version` is missing or not `1.0`.
    BadA2aVersion(String),
    /// Content-Digest missing, duplicated, mismatched, or wrong algorithm.
    ContentDigest(DeliveryError),
    /// One or more required extension URIs were not activated (§10.1).
    MissingRequiredExtensions(Vec<String>),
}

/// Applies the ingress gates and idempotency peek.
pub fn admit(
    store: &Store,
    required_extensions: &BTreeSet<String>,
    req: &Ingress,
) -> Result<Admit, StoreError> {
    if !media_type_matches(req.content_type, A2A_MEDIA_TYPE) {
        return Ok(Admit::Rejected(Reject::UnsupportedMediaType));
    }

    match req.a2a_version {
        Some(v) if profile::validate_a2a_version(v).is_ok() => {}
        other => {
            return Ok(Admit::Rejected(Reject::BadA2aVersion(
                other.unwrap_or_default().to_owned(),
            )))
        }
    }

    if let Err(e) = verify_content_digest(req.content_digest.unwrap_or_default(), req.body) {
        return Ok(Admit::Rejected(Reject::ContentDigest(e)));
    }

    let activated: BTreeSet<&str> = req
        .activated_extensions
        .iter()
        .map(String::as_str)
        .collect();
    let missing: Vec<String> = required_extensions
        .iter()
        .filter(|r| !activated.contains(r.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Ok(Admit::Rejected(Reject::MissingRequiredExtensions(missing)));
    }

    let covered = CoveredValues {
        peer: req.peer.to_owned(),
        message_id: req.message_id.to_owned(),
        body_digest: body_digest(req.body),
        interface_url: req.interface_url.to_owned(),
        tenant: req.tenant.map(str::to_owned),
        a2a_version: req.a2a_version.unwrap_or(A2A_VERSION).to_owned(),
        extensions: req.activated_extensions.to_vec(),
        content_type: req.content_type.to_owned(),
        http_method: req.method.to_owned(),
    }
    .normalized();

    Ok(match store.peek(&covered)? {
        Receipt::Fresh => Admit::Accept(covered),
        Receipt::Duplicate { task_id, response } => Admit::Duplicate { task_id, response },
        Receipt::Conflict => Admit::Conflict,
    })
}

/// Matches the media type ignoring any parameters (`; charset=…`) and case.
fn media_type_matches(header: &str, expected: &str) -> bool {
    header
        .split(';')
        .next()
        .map(|m| m.trim().eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use akson_store::delivery::content_digest;
    use akson_store::envelope::Kek;
    use akson_store::{ExternalCheckpoint, Store};

    fn store() -> Store {
        let cp = ExternalCheckpoint {
            state_generation: 0,
            trusted_time: 0,
            rollback_detectable: true,
        };
        Store::open_in_memory(&Kek::from_bytes([4u8; 32]), cp).unwrap()
    }

    const BODY: &[u8] = br#"{"messageId":"m1"}"#;

    fn ingress<'a>(digest: &'a str, exts: &'a [String]) -> Ingress<'a> {
        Ingress {
            peer: "agent-b",
            method: "POST",
            content_type: "application/a2a+json",
            a2a_version: Some("1.0"),
            content_digest: Some(digest),
            activated_extensions: exts,
            interface_url: "https://agent.example/a2a",
            tenant: None,
            message_id: "m1",
            body: BODY,
        }
    }

    #[test]
    fn accepts_a_well_formed_fresh_request() {
        let digest = content_digest(BODY);
        let out = admit(&store(), &BTreeSet::new(), &ingress(&digest, &[])).unwrap();
        assert!(matches!(out, Admit::Accept(_)));
    }

    #[test]
    fn rejects_wrong_media_type() {
        let digest = content_digest(BODY);
        let mut req = ingress(&digest, &[]);
        req.content_type = "application/json";
        assert!(matches!(
            admit(&store(), &BTreeSet::new(), &req).unwrap(),
            Admit::Rejected(Reject::UnsupportedMediaType)
        ));
    }

    #[test]
    fn accepts_media_type_with_charset_param() {
        let digest = content_digest(BODY);
        let mut req = ingress(&digest, &[]);
        req.content_type = "application/a2a+json; charset=utf-8";
        assert!(matches!(
            admit(&store(), &BTreeSet::new(), &req).unwrap(),
            Admit::Accept(_)
        ));
    }

    #[test]
    fn rejects_bad_a2a_version() {
        let digest = content_digest(BODY);
        let mut req = ingress(&digest, &[]);
        req.a2a_version = Some("0.3");
        assert!(matches!(
            admit(&store(), &BTreeSet::new(), &req).unwrap(),
            Admit::Rejected(Reject::BadA2aVersion(_))
        ));
    }

    #[test]
    fn rejects_mismatched_content_digest() {
        let wrong = content_digest(b"different body");
        assert!(matches!(
            admit(&store(), &BTreeSet::new(), &ingress(&wrong, &[])).unwrap(),
            Admit::Rejected(Reject::ContentDigest(_))
        ));
    }

    #[test]
    fn rejects_missing_required_extension() {
        let digest = content_digest(BODY);
        let mut required = BTreeSet::new();
        required.insert("https://akson.cc/ext/contract/v1".to_owned());
        assert!(matches!(
            admit(&store(), &required, &ingress(&digest, &[])).unwrap(),
            Admit::Rejected(Reject::MissingRequiredExtensions(_))
        ));
    }

    #[test]
    fn duplicate_and_conflict_after_commit() {
        let store = store();
        let digest = content_digest(BODY);
        // First sight is accepted; commit it with a response and Task id.
        let covered = match admit(&store, &BTreeSet::new(), &ingress(&digest, &[])).unwrap() {
            Admit::Accept(c) => c,
            other => panic!("expected accept, got {other:?}"),
        };
        store
            .receive_request(&covered, BODY, b"RESPONSE", Some("task-1"), "task", 100)
            .unwrap();

        // The same request now replays the saved response.
        match admit(&store, &BTreeSet::new(), &ingress(&digest, &[])).unwrap() {
            Admit::Duplicate { task_id, response } => {
                assert_eq!(task_id.as_deref(), Some("task-1"));
                assert_eq!(response, b"RESPONSE");
            }
            other => panic!("expected duplicate, got {other:?}"),
        }

        // Same Message id, different body → different covered value → conflict.
        let other_body: &[u8] = br#"{"messageId":"m1","x":1}"#;
        let other_digest = content_digest(other_body);
        let mut req = ingress(&other_digest, &[]);
        req.body = other_body;
        assert!(matches!(
            admit(&store, &BTreeSet::new(), &req).unwrap(),
            Admit::Conflict
        ));
    }
}
