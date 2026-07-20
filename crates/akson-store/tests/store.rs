//! Storage exit-criteria tests (design §20.7): no plaintext in the database,
//! WAL, or side files; and a marker sealed in a column is still recoverable.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use akson_crypto::identity::{Fingerprint, PeerIdentity};
use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, Store, StoredPeer};

const MARKER: &str = "PLAINTEXT-MARKER-7f3a9c2e";

fn checkpoint() -> ExternalCheckpoint {
    ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    }
}

fn peer_with_note(note: &str) -> StoredPeer {
    let vk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    StoredPeer {
        identity: PeerIdentity {
            issuer: None,
            agent_id: "agent-a".to_owned(),
            workload_id: None,
            endpoint_id: "ep-1".to_owned(),
            tls_cert: Fingerprint::cert_sha256(b"der"),
            agent_card_key: Fingerprint::jwk(&vk),
            key_bindings: vec![],
            security_projection_digest: Fingerprint::json_sha256(b"{}"),
            full_card_digest: Fingerprint::json_sha256(b"{}"),
        },
        local_note: note.to_owned(),
    }
}

/// Asserts the marker appears in no file under `dir` (db, `-wal`, `-shm`, …).
fn assert_no_plaintext(dir: &Path) {
    let needle = MARKER.as_bytes();
    let mut scanned = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        scanned += 1;
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "plaintext marker leaked into {path:?}"
        );
    }
    assert!(scanned > 0, "expected at least the database file to scan");
}

#[test]
fn no_plaintext_in_db_or_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let kek = Kek::from_bytes([3u8; 32]);

    {
        let store = Store::open(&path, &kek, checkpoint()).unwrap();
        store.put_peer(&peer_with_note(MARKER)).unwrap();
        store.audit(1, "pair.created", "peer=agent-a").unwrap();

        // While the connection is open the write typically lives in the WAL;
        // scanning every file proves the marker is nowhere in cleartext.
        assert_no_plaintext(dir.path());

        // ...and it is genuinely stored, only sealed — not dropped.
        assert_eq!(
            store.get_peer("agent-a").unwrap().unwrap().local_note,
            MARKER
        );
    }

    // After close, the data is flushed to the main database file; still sealed.
    assert_no_plaintext(dir.path());

    // A fresh open with the same KEK recovers the sealed value.
    let store = Store::open(&path, &kek, checkpoint()).unwrap();
    assert_eq!(
        store.get_peer("agent-a").unwrap().unwrap().local_note,
        MARKER
    );
}
