//! The persistent (SQLite) pairing ledger (design §8.2): consume-once with
//! idempotent replay, GC of expired records, and survival across a reopen.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axon_pairing::invitation::Invitation;
use axon_pairing::state_machine::{accept, Accepted, PairingLedger};
use axon_store::envelope::Kek;
use axon_store::{ExternalCheckpoint, Store};

fn checkpoint() -> ExternalCheckpoint {
    ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    }
}

fn invitation() -> (
    String,
    [u8; 32],
    axon_pairing::invitation::PendingInvitation,
) {
    let (artifact, pending) = Invitation::create(
        "https://inviter/bootstrap".to_owned(),
        "aa".repeat(32),
        "kid".to_owned(),
        1_000,
        900,
        5,
    );
    let verifier = pending.verifier();
    (artifact.secret, verifier, pending)
}

#[test]
fn consume_once_replay_and_conflict() {
    let mut store = Store::open_in_memory(&Kek::from_bytes([5u8; 32]), checkpoint()).unwrap();
    let (secret, verifier, pending) = invitation();
    store.put_active(verifier, pending).unwrap();

    assert_eq!(
        accept(&mut store, &secret, [1u8; 32], b"RESP".to_vec(), 1_100).unwrap(),
        Accepted::Paired {
            response: b"RESP".to_vec()
        }
    );
    // Exact replay returns the saved response from pending_pairs.
    assert_eq!(
        accept(&mut store, &secret, [1u8; 32], b"OTHER".to_vec(), 1_200).unwrap(),
        Accepted::Replay {
            response: b"RESP".to_vec()
        }
    );
    // A changed transcript under the same secret is an attack.
    assert_eq!(
        accept(&mut store, &secret, [2u8; 32], b"x".to_vec(), 1_300).unwrap(),
        Accepted::TranscriptConflict
    );
}

#[test]
fn purge_removes_expired_consumed_records() {
    let mut store = Store::open_in_memory(&Kek::from_bytes([5u8; 32]), checkpoint()).unwrap();
    let (secret, verifier, pending) = invitation();
    store.put_active(verifier, pending).unwrap();
    accept(&mut store, &secret, [1u8; 32], b"RESP".to_vec(), 1_100).unwrap(); // expires_at = 1_900

    // Before expiry, the retry replays.
    assert!(matches!(
        accept(&mut store, &secret, [1u8; 32], b"x".to_vec(), 1_500).unwrap(),
        Accepted::Replay { .. }
    ));
    // After expiry, GC removes the record and the secret is unknown again.
    store.purge_expired_pairing(2_000).unwrap();
    assert_eq!(
        accept(&mut store, &secret, [1u8; 32], b"x".to_vec(), 2_100).unwrap(),
        Accepted::BadSecret
    );
}

#[test]
fn invitation_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let kek = Kek::from_bytes([5u8; 32]);
    let (secret, verifier, pending) = invitation();

    {
        let mut store = Store::open(&path, &kek, checkpoint()).unwrap();
        store.put_active(verifier, pending).unwrap();
    }
    // A restart: the sealed invitation is still there and can be consumed.
    let mut store = Store::open(&path, &kek, checkpoint()).unwrap();
    assert_eq!(
        accept(&mut store, &secret, [1u8; 32], b"RESP".to_vec(), 1_100).unwrap(),
        Accepted::Paired {
            response: b"RESP".to_vec()
        }
    );
}
