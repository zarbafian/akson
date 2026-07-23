//! Provisional imports and the knock log (design §8.2, ADR-0013/0015, store
//! slice): the import is the one trust act, labels are local and reusable
//! only after removal, epochs advance on removal so nothing pre-removal can
//! commit again, and knocks dedupe instead of growing rows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use akson_store::envelope::Kek;
use akson_store::{ExternalCheckpoint, ImportOutcome, Store};

const ROOT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn store() -> Store {
    let cp = ExternalCheckpoint {
        state_generation: 0,
        trusted_time: 0,
        rollback_detectable: true,
    };
    Store::open_in_memory(&Kek::from_bytes([7u8; 32]), cp).unwrap()
}

#[test]
fn import_roundtrip_and_label_resolution() {
    let s = store();
    assert_eq!(
        s.add_peer_import(ROOT_A, "dana-claude", "198.51.100.7:18444", 100)
            .unwrap(),
        ImportOutcome::Added
    );
    let by_root = s.peer_import(ROOT_A).unwrap().unwrap();
    let by_label = s.peer_import_by_label("dana-claude").unwrap().unwrap();
    assert_eq!(by_root, by_label);
    assert_eq!(by_root.epoch, 1);
    assert_eq!(by_root.endpoint_hint, "198.51.100.7:18444");
    assert_eq!(s.list_peer_imports().unwrap().len(), 1);
}

#[test]
fn duplicate_root_is_reported_never_overwritten() {
    let s = store();
    s.add_peer_import(ROOT_A, "dana-claude", "a:1", 100).unwrap();
    assert_eq!(
        s.add_peer_import(ROOT_A, "other-name", "b:2", 200).unwrap(),
        ImportOutcome::DuplicateRoot
    );
    let row = s.peer_import(ROOT_A).unwrap().unwrap();
    assert_eq!(row.label, "dana-claude");
    assert_eq!(row.endpoint_hint, "a:1");
}

#[test]
fn label_held_by_another_live_import_is_refused() {
    let s = store();
    s.add_peer_import(ROOT_A, "claude", "a:1", 100).unwrap();
    assert_eq!(
        s.add_peer_import(ROOT_B, "claude", "b:2", 200).unwrap(),
        ImportOutcome::LabelTaken
    );
    assert!(s.peer_import(ROOT_B).unwrap().is_none());
    // Same-name peers coexist under distinct labels — the #2 fix.
    assert_eq!(
        s.add_peer_import(ROOT_B, "sam-claude", "b:2", 200).unwrap(),
        ImportOutcome::Added
    );
    assert_eq!(s.list_peer_imports().unwrap().len(), 2);
}

#[test]
fn removal_tombstones_bumps_epoch_and_frees_label() {
    let s = store();
    s.add_peer_import(ROOT_A, "claude", "a:1", 100).unwrap();
    assert!(s.remove_peer_import(ROOT_A, 150).unwrap());
    assert!(s.peer_import(ROOT_A).unwrap().is_none());
    assert!(s.peer_import_by_label("claude").unwrap().is_none());
    assert!(s.list_peer_imports().unwrap().is_empty());
    // The freed label may be reused by a different root, inheriting nothing.
    assert_eq!(
        s.add_peer_import(ROOT_B, "claude", "b:2", 200).unwrap(),
        ImportOutcome::Added
    );
    assert_eq!(s.peer_import(ROOT_B).unwrap().unwrap().epoch, 1);
    // Removing again is a no-op: nothing live holds the root.
    assert!(!s.remove_peer_import(ROOT_A, 250).unwrap());
}

#[test]
fn re_add_after_removal_is_a_new_epoch() {
    let s = store();
    s.add_peer_import(ROOT_A, "claude", "a:1", 100).unwrap();
    s.remove_peer_import(ROOT_A, 150).unwrap();
    assert_eq!(
        s.add_peer_import(ROOT_A, "claude-again", "a:9", 300).unwrap(),
        ImportOutcome::Added
    );
    let revived = s.peer_import(ROOT_A).unwrap().unwrap();
    // Epoch advanced at removal: an introduction begun before the removal
    // compares against 1 and can no longer commit.
    assert_eq!(revived.epoch, 2);
    assert_eq!(revived.label, "claude-again");
    assert_eq!(revived.endpoint_hint, "a:9");
}

#[test]
fn update_refreshes_label_and_hint_but_never_epoch() {
    let s = store();
    s.add_peer_import(ROOT_A, "claude", "a:1", 100).unwrap();
    s.add_peer_import(ROOT_B, "sam", "b:1", 100).unwrap();
    assert_eq!(
        s.update_peer_import(ROOT_A, Some("dana"), Some("a:2")).unwrap(),
        ImportOutcome::Updated
    );
    let row = s.peer_import(ROOT_A).unwrap().unwrap();
    assert_eq!((row.label.as_str(), row.endpoint_hint.as_str()), ("dana", "a:2"));
    assert_eq!(row.epoch, 1);
    // Renaming onto another live import's label is refused...
    assert_eq!(
        s.update_peer_import(ROOT_A, Some("sam"), None).unwrap(),
        ImportOutcome::LabelTaken
    );
    // ...while re-asserting your own label is fine.
    assert_eq!(
        s.update_peer_import(ROOT_A, Some("dana"), None).unwrap(),
        ImportOutcome::Updated
    );
    // A tombstoned root cannot be updated back to life.
    s.remove_peer_import(ROOT_A, 200).unwrap();
    assert_eq!(
        s.update_peer_import(ROOT_A, Some("ghost"), None).unwrap(),
        ImportOutcome::UnknownRoot
    );
}

#[test]
fn knocks_dedupe_count_and_order() {
    let s = store();
    s.record_knock(ROOT_A, "203.0.113.5", "not-imported", 100).unwrap();
    s.record_knock(ROOT_A, "203.0.113.5", "not-imported", 130).unwrap();
    s.record_knock(ROOT_B, "203.0.113.6", "bad-version", 120).unwrap();
    let knocks = s.knocks().unwrap();
    assert_eq!(knocks.len(), 2);
    // Most recent first.
    assert_eq!(knocks[0].claimed_root, ROOT_A);
    assert_eq!((knocks[0].count, knocks[0].first_at, knocks[0].last_at), (2, 100, 130));
    assert_eq!(knocks[1].count, 1);
}

#[test]
fn knock_log_is_capped_but_known_triples_still_count() {
    let s = store();
    for i in 0..1024 {
        s.record_knock(ROOT_A, &format!("src-{i}"), "not-imported", i).unwrap();
    }
    // A new triple at the cap is dropped...
    s.record_knock(ROOT_B, "overflow", "not-imported", 5000).unwrap();
    let knocks = s.knocks().unwrap();
    assert_eq!(knocks.len(), 1024);
    assert!(knocks.iter().all(|k| k.claimed_root == ROOT_A));
    // ...while an existing one still counts up.
    s.record_knock(ROOT_A, "src-7", "not-imported", 6000).unwrap();
    let bumped = s
        .knocks()
        .unwrap()
        .into_iter()
        .find(|k| k.source == "src-7")
        .unwrap();
    assert_eq!((bumped.count, bumped.last_at), (2, 6000));
}
