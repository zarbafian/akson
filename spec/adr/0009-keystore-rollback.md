# ADR-0009: Keystore abstraction and rollback checkpoint

Status: accepted
Date: 2026-07-16

## Context

Design §8.1 keeps signing keys per purpose; §15.5 requires private keys to
live in the OS keystore or an HSM (outside database backups), and requires a
**monotonic state generation** — a rollback checkpoint — so a restored-from-
backup daemon can detect that its persistent state was rewound. Where no
protected keystore or TPM exists, §15.5 says to report rollback detection
unavailable and degrade, not to block install.

The concrete OS mechanisms differ per platform (Secret Service / libsecret on
Linux, Keychain on macOS, Credential Manager on Windows) and a TPM2 NV counter
is a further, optional source of monotonicity. None of these should be on the
default build path (they pull system libraries and complicate `cargo test`),
and at-rest encryption of key material is a separate concern (envelope
encryption, ADR-0005, lands with the store in M4).

## Decision

`axon-crypto` exposes a **`KeyStore` trait** — the single seam pairing, the
store, and rotation use — with two responsibilities:

1. Purpose-addressed custody of secret key material: `put`/`get`/`list` keyed
   by `KeyPurpose` (plus generation), returning purpose-bound keys so a caller
   cannot pull a key out for the wrong role.
2. A monotonic `state_generation` counter (`read`/`advance`) that only ever
   increases — the rollback checkpoint.

The default implementation is `MemoryKeyStore` (used by tests and ephemeral
runs). Production adapters are additive and **off by default**:

- `os-keystore` feature → a `keyring`-crate adapter (Secret Service, Keychain,
  Credential Manager). Secret keys are stored wrapped; the wrapping key is the
  envelope-encryption concern of ADR-0005.
- `tpm` feature → a `tss-esapi` adapter backing `state_generation` with a TPM2
  NV monotonic counter.

When neither a protected keystore nor a TPM is available, the daemon records
`rollback_detection: unavailable` and continues (design §15.5), rather than
failing to start. The checkpoint value is compared against the store's
persisted generation on open (wired in M4); disagreement is a fail-closed
freshness fault (design §15.5), not a silent repair.

## Consequences

- `cargo build`/`cargo test` stay pure Rust with no system dependencies;
  enabling `os-keystore`/`tpm` is opt-in and CI-gated separately.
- The trait lets M4 (store), M6 (pairing), and rotation depend on custody
  without knowing the platform backend.
- At-rest key encryption is deferred to ADR-0005; this ADR governs *where*
  keys and the monotonic counter live, not *how* bytes are encrypted.
- Rollback handling is testable now against `MemoryKeyStore` and the
  generation counter; the TPM path is exercised behind its feature.
