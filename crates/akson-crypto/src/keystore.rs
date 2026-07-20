//! Key custody and the rollback checkpoint (ADR-0009, design §15.5).
//!
//! `KeyStore` is the one seam pairing, the store, and rotation use to hold
//! secret keys per purpose and to read/advance a **monotonic state
//! generation** — the counter that lets a restored-from-backup daemon notice
//! its state was rewound. `MemoryKeyStore` is the default (tests, ephemeral
//! runs); the OS-keystore and TPM backends are additive adapters behind the
//! `os-keystore`/`tpm` features (ADR-0009), not part of the default build.
//!
//! What you write:
//! ```
//! use akson_crypto::keystore::{KeyStore, MemoryKeyStore};
//! use akson_crypto::keypair::PurposeKey;
//! use akson_crypto::purpose::KeyPurpose;
//! let mut ks = MemoryKeyStore::new();
//! ks.put(0, PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32])).unwrap();
//! let g1 = ks.advance_state_generation(); // 1; only ever increases
//! assert!(ks.latest(KeyPurpose::AgentCard).is_some());
//! ```

use crate::keypair::PurposeKey;
use crate::purpose::KeyPurpose;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("a key for {purpose:?} generation {generation} already exists")]
    DuplicateGeneration {
        purpose: KeyPurpose,
        generation: u64,
    },
}

/// Whether this backend can detect state rollback. `MemoryKeyStore` cannot;
/// an OS keystore or TPM counter can. Callers degrade per design §15.5 rather
/// than block when detection is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackDetection {
    Available,
    Unavailable,
}

/// Custody of purpose-bound secret keys plus the monotonic rollback counter.
/// Object-safe, so a daemon can hold `Box<dyn KeyStore>` and swap backends.
pub trait KeyStore {
    /// Stores `key` at `generation`. Fails rather than overwrite an existing
    /// (purpose, generation) — rotation always uses a fresh, higher generation.
    fn put(&mut self, generation: u64, key: PurposeKey) -> Result<(), StoreError>;

    /// The key for exactly this purpose and generation, if present.
    fn get(&self, purpose: KeyPurpose, generation: u64) -> Option<&PurposeKey>;

    /// The highest-generation key held for `purpose` (the current one).
    fn latest(&self, purpose: KeyPurpose) -> Option<&PurposeKey>;

    /// The purposes for which at least one key is held.
    fn purposes(&self) -> Vec<KeyPurpose>;

    /// The current monotonic state generation (the rollback checkpoint).
    fn state_generation(&self) -> u64;

    /// Advances the state generation by one and returns the new value. The
    /// counter only ever increases; on a real backend this write is what a
    /// rollback would fail to reproduce.
    fn advance_state_generation(&mut self) -> u64;

    /// Whether this backend can detect rollback (design §15.5).
    fn rollback_detection(&self) -> RollbackDetection {
        RollbackDetection::Unavailable
    }
}

/// In-memory `KeyStore`: the default for tests and ephemeral runs. Holds no
/// wrapping and reports rollback detection unavailable.
#[derive(Default)]
pub struct MemoryKeyStore {
    keys: HashMap<(KeyPurpose, u64), PurposeKey>,
    state_generation: u64,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn put(&mut self, generation: u64, key: PurposeKey) -> Result<(), StoreError> {
        let slot = (key.purpose(), generation);
        if self.keys.contains_key(&slot) {
            return Err(StoreError::DuplicateGeneration {
                purpose: slot.0,
                generation,
            });
        }
        self.keys.insert(slot, key);
        Ok(())
    }

    fn get(&self, purpose: KeyPurpose, generation: u64) -> Option<&PurposeKey> {
        self.keys.get(&(purpose, generation))
    }

    fn latest(&self, purpose: KeyPurpose) -> Option<&PurposeKey> {
        self.keys
            .iter()
            .filter(|((p, _), _)| *p == purpose)
            .max_by_key(|((_, g), _)| *g)
            .map(|(_, k)| k)
    }

    fn purposes(&self) -> Vec<KeyPurpose> {
        let mut seen: Vec<KeyPurpose> = Vec::new();
        for (p, _) in self.keys.keys() {
            if !seen.contains(p) {
                seen.push(*p);
            }
        }
        seen
    }

    fn state_generation(&self) -> u64 {
        self.state_generation
    }

    fn advance_state_generation(&mut self) -> u64 {
        self.state_generation += 1;
        self.state_generation
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_finds_latest() {
        let mut ks = MemoryKeyStore::new();
        ks.put(0, PurposeKey::from_seed(KeyPurpose::AgentCard, &[1u8; 32]))
            .unwrap();
        ks.put(1, PurposeKey::from_seed(KeyPurpose::AgentCard, &[2u8; 32]))
            .unwrap();
        let latest = ks.latest(KeyPurpose::AgentCard).unwrap();
        assert_eq!(
            latest.thumbprint(),
            PurposeKey::from_seed(KeyPurpose::AgentCard, &[2u8; 32]).thumbprint()
        );
        assert_eq!(ks.purposes(), vec![KeyPurpose::AgentCard]);
    }

    #[test]
    fn rejects_duplicate_generation() {
        let mut ks = MemoryKeyStore::new();
        ks.put(0, PurposeKey::from_seed(KeyPurpose::Evidence, &[1u8; 32]))
            .unwrap();
        assert!(matches!(
            ks.put(0, PurposeKey::from_seed(KeyPurpose::Evidence, &[9u8; 32])),
            Err(StoreError::DuplicateGeneration { .. })
        ));
    }

    #[test]
    fn state_generation_only_increases() {
        let mut ks = MemoryKeyStore::new();
        assert_eq!(ks.state_generation(), 0);
        assert_eq!(ks.advance_state_generation(), 1);
        assert_eq!(ks.advance_state_generation(), 2);
        assert_eq!(ks.state_generation(), 2);
        assert_eq!(ks.rollback_detection(), RollbackDetection::Unavailable);
    }
}
