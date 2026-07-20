# ADR-0005: Envelope encryption for sensitive columns

Status: accepted
Date: 2026-07-16

## Context

Design §15.1 requires sensitive columns and blobs to be encrypted before they
reach SQLite, with an audited envelope-encryption library and a key protected
by the OS keystore or HSM, so that WAL files, temp files, crash dumps, and
backups never contain plaintext task bodies. Akson "adopts the library's
reviewed ciphertext format; it does not create one." ADR-0003 already fixed
the storage boundary at the application layer (not SQLCipher/full-db).

Envelope encryption means: a data-encryption key (DEK) encrypts the values, and
a key-encryption key (KEK) — held in the OS keystore (ADR-0009) — encrypts the
DEK. Only the wrapped DEK is persisted.

Candidates for the AEAD: RustCrypto `chacha20poly1305` (`XChaCha20Poly1305`),
`aes-gcm`, or a `ring`/`aws-lc-rs` binding. Higher-level `age` is file- and
asymmetric-oriented, heavier than symmetric column sealing needs.

## Decision

Use **`XChaCha20Poly1305`** (RustCrypto `chacha20poly1305`, security-audited,
pure Rust — no OpenSSL/`ring` on the storage path) as the AEAD for both column
sealing and DEK wrapping.

- **DEK:** one random 256-bit key per database, generated at init and stored
  only in wrapped form in the `meta` table.
- **KEK:** 32 bytes supplied at `Store::open`; its custody is the keystore's
  (ADR-0009). The store never persists the KEK.
- **Sealed value format (versioned):** `0x01 ‖ nonce(24) ‖ ciphertext‖tag`.
  The 24-byte random nonce makes many-values-under-one-key safe without nonce
  bookkeeping; the leading version byte lets the scheme rotate. This is
  framing around the library's own AEAD output, not a bespoke construction.
- **AAD binding:** every seal takes a context label (e.g. `"peers.local_note"`)
  as additional authenticated data, so a ciphertext authenticated for one
  column cannot be relocated to another.

`aes-gcm` is rejected for its 96-bit nonce (reuse risk across many values);
`ring`/OpenSSL for the C dependency; SQLCipher as already excluded by ADR-0003.

## Consequences

- The design §20.7 plaintext-scan test seals a planted marker and asserts it
  never appears in the db file, WAL, or temp directory.
- DEK rotation is a re-seal migration; the version byte lets old and new
  ciphertexts coexist during it.
- Blobs above a threshold may later move to an encrypted file store (ADR-0003)
  reusing the same seal format — a storage-crate change, not a format change.
- The KEK wiring to the OS keystore/HSM is ADR-0009; this ADR governs the
  ciphertext, not the KEK's custody.
