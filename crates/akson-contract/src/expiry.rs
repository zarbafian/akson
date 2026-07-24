//! Contract validity against trusted time (design §9.3, §10.2, §8.5).
//!
//! Expiry is an authority boundary, not a performer assertion: a contract is
//! effective only from its `created_at` until its `expires_at`, evaluated
//! against the caller's *trusted* time (the §8.5 monotonic floor the store
//! supplies), never the raw wall clock. Outside that window the contract cannot
//! authorize work — an expired proposal is rejected before acceptance, and an
//! accepted contract's authority lapses at expiry.
//!
//! What you write:
//! ```
//! use akson_contract::{validity, Validity};
//! # use akson_contract::parse_payload;
//! # use serde_json::json;
//! # let value = json!({
//! #   "schema_version": 1, "contract_id": "00000000-0000-4000-8000-000000000000",
//! #   "revision": 0, "task_type": "https://akson.invalid/t", "message_id": "m1",
//! #   "requester": {"issuer": "a", "agent": "b", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "performer": {"issuer": "c", "agent": "d", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
//! #   "objective": "o", "inputs": [], "deliverables": [{"role": "r", "media_type": "text/plain"}],
//! #   "evidence_slots": [], "requested_capabilities": [], "processor_constraints": {"disclosure": "none"},
//! #   "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
//! #   "result_recipient": "request-origin",
//! #   "created_at": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z"
//! # });
//! # let contract = parse_payload(&akson_ext::jcs::canonical_bytes(&value).unwrap()).unwrap().contract;
//! // Trusted 'now' (unix seconds) is supplied by the store's §8.5 time floor.
//! let mid_2026 = 1_781_000_000;
//! assert_eq!(validity(&contract, mid_2026).unwrap(), Validity::Valid);
//! let year_2028 = 1_830_000_000;
//! assert_eq!(validity(&contract, year_2028).unwrap(), Validity::Expired);
//! ```

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::contract::Contract;

/// Where the trusted `now` falls relative to a contract's effective window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// `created_at <= now < expires_at` — the contract may authorize work.
    Valid,
    /// `now < created_at` — the contract is not yet effective (future-dated).
    NotYetValid,
    /// `now >= expires_at` — the authority window has closed.
    Expired,
}

/// A timestamp that passed schema validation but could not be parsed as RFC 3339.
/// Reachable only on a corrupt or misvalidated contract; the caller fails closed.
#[derive(Debug, thiserror::Error)]
#[error("contract timestamp {field} is not a parseable RFC 3339 instant")]
pub struct TimestampError {
    pub field: &'static str,
}

/// Clock-skew tolerance applied to the *start* of the window only. A performer
/// whose clock trails the requester's by a fraction of a second must not reject a
/// freshly-signed contract as "not yet valid" — `created_at` is truncated to whole
/// seconds, so even sub-second skew across a second boundary would otherwise trip
/// it. The lapse (`expires_at`) side takes NO leeway: trusted time must never revive
/// expired authority.
const NOT_YET_VALID_LEEWAY_SECS: i64 = 5;

/// Evaluates a contract's [`Validity`] at trusted `now_unix` (unix seconds).
///
/// The window is half-open: effective at `created_at` (minus a small clock-skew
/// leeway), lapsed at `expires_at`. `now_unix` MUST be the trusted time (the §8.5
/// floor), so a rolled-back wall clock cannot revive an expired contract.
pub fn validity(contract: &Contract, now_unix: i64) -> Result<Validity, TimestampError> {
    let created = parse(&contract.created_at, "created_at")?;
    let expires = parse(&contract.expires_at, "expires_at")?;
    // An empty or inverted window (created >= expires) can never authorize work —
    // check this BEFORE the start-side leeway, so the tolerance cannot make a
    // zero-length interval momentarily Valid (codex review).
    if created >= expires {
        return Ok(Validity::Expired);
    }
    Ok(if now_unix < created - NOT_YET_VALID_LEEWAY_SECS {
        Validity::NotYetValid
    } else if now_unix >= expires {
        Validity::Expired
    } else {
        Validity::Valid
    })
}

/// The contract's `expires_at` as unix seconds — the retention bound the store
/// keeps a stored revision to (design §10.2).
pub fn expires_at_unix(contract: &Contract) -> Result<i64, TimestampError> {
    parse(&contract.expires_at, "expires_at")
}

/// The contract's task deadline (`limits.deadline`) as unix seconds — the requested
/// completion bound, distinct from the `expires_at` authority window.
pub fn deadline_unix(contract: &Contract) -> Result<i64, TimestampError> {
    parse(&contract.limits.deadline, "deadline")
}

fn parse(s: &str, field: &'static str) -> Result<i64, TimestampError> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map(|dt| dt.unix_timestamp())
        .map_err(|_| TimestampError { field })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::parse_payload;
    use akson_ext::jcs;
    use serde_json::{json, Value};

    fn contract(created: &str, expires: &str) -> Contract {
        let v = json!({
            "schema_version": 1,
            "contract_id": "00000000-0000-4000-8000-000000000000",
            "revision": 0,
            "task_type": "https://akson.invalid/t",
            "message_id": "m1",
            "requester": {"issuer": "a", "agent": "b", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "performer": {"issuer": "c", "agent": "d", "root": "root-fixture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "objective": "o",
            "inputs": [],
            "deliverables": [{"role": "r", "media_type": "text/plain"}],
            "evidence_slots": [],
            "requested_capabilities": [],
            "processor_constraints": {"disclosure": "none"},
            "limits": {"deadline": "2030-01-01T00:00:00Z", "max_response_bytes": 1024},
            "result_recipient": "request-origin",
            "created_at": Value::from(created),
            "expires_at": Value::from(expires),
        });
        parse_payload(&jcs::canonical_bytes(&v).unwrap())
            .unwrap()
            .contract
    }

    // 2026-06-01T00:00:00Z and neighbors, as unix seconds.
    const BEFORE: i64 = 1_735_689_600; // 2025-01-01
    const DURING: i64 = 1_764_547_200; // 2025-12-01 (within 2025..2027 window)
    const AFTER: i64 = 1_830_297_600; // 2028-01-01

    #[test]
    fn valid_within_the_window() {
        let c = contract("2025-06-01T00:00:00Z", "2027-06-01T00:00:00Z");
        assert_eq!(validity(&c, DURING).unwrap(), Validity::Valid);
    }

    #[test]
    fn expired_at_and_after_the_boundary() {
        let c = contract("2025-06-01T00:00:00Z", "2027-06-01T00:00:00Z");
        assert_eq!(validity(&c, AFTER).unwrap(), Validity::Expired);
        // The window is half-open: exactly at expires_at is already expired.
        let expires = OffsetDateTime::parse("2027-06-01T00:00:00Z", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        assert_eq!(validity(&c, expires).unwrap(), Validity::Expired);
    }

    #[test]
    fn not_yet_valid_before_creation() {
        let c = contract("2025-06-01T00:00:00Z", "2027-06-01T00:00:00Z");
        assert_eq!(validity(&c, BEFORE).unwrap(), Validity::NotYetValid);
        // Exactly at created_at is already effective (half-open lower bound).
        let created = OffsetDateTime::parse("2025-06-01T00:00:00Z", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        assert_eq!(validity(&c, created).unwrap(), Validity::Valid);
    }

    #[test]
    fn a_small_clock_skew_at_the_start_is_tolerated() {
        // A freshly-signed contract whose created_at is a little ahead of the
        // performer's trusted-now (the requester's clock leads across a second
        // boundary) must still be effective — the transient the two-machine bench
        // hit. Beyond the leeway it is genuinely not-yet-valid.
        let c = contract("2025-06-01T00:00:03Z", "2027-06-01T00:00:00Z");
        let created = OffsetDateTime::parse("2025-06-01T00:00:03Z", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        assert_eq!(validity(&c, created - 3).unwrap(), Validity::Valid);
        assert_eq!(validity(&c, created - 6).unwrap(), Validity::NotYetValid);
    }

    #[test]
    fn an_inverted_window_is_never_valid_despite_the_leeway() {
        // created after expires: the leeway must not make this Valid at any `now`.
        let c = contract("2027-06-01T00:00:00Z", "2025-06-01T00:00:00Z");
        for now in [BEFORE, DURING, AFTER] {
            assert_eq!(validity(&c, now).unwrap(), Validity::Expired);
        }
    }
}
