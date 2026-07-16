# ADR-0011: TLS stack and self-issued endpoint certificates

Status: accepted
Date: 2026-07-16

## Context

Design §9.1 pins the v1 transport to mutual TLS 1.3 with no downgrade, and
§8.3 allows self-issued X.509 endpoint certificates in the personal profile,
pinned by SHA-256/DER fingerprint at pairing (§8.1). §19 asks to "select
reviewed TLS, X.509, ... libraries."

`rustls` is the clear TLS choice (memory-safe, TLS 1.3, widely deployed). It
requires a `CryptoProvider`, and the mature ones — `aws-lc-rs` (default) and
`ring` — are C/assembly. The rest of Axon's crypto path (Ed25519 signing via
`ed25519-dalek`, sealing via RustCrypto `chacha20poly1305`) is deliberately
pure Rust with no C.

## Decision

Use **`rustls` with the pure-Rust `rustls-rustcrypto` provider** and generate
self-issued Ed25519 endpoint certificates with the RustCrypto **`x509-cert`**
builder, keeping the entire crypto surface pure Rust and consistent with the
existing signing/sealing stack — no C anywhere.

- TLS 1.3 only; mutual TLS mandatory; no cipher/version/auth downgrade (§9.1).
- Endpoint certificates are self-signed over the `tls-endpoint` purpose key;
  certificate signing goes through the purpose gate (a key bound to another
  role fails closed). The peer pins the SHA-256/DER fingerprint
  (`identity::Fingerprint::cert_sha256`) at pairing.
- The `CryptoProvider` is the swap seam: moving to `aws-lc-rs` later is a
  localized change, not a rewrite.

**Accepted tradeoff (explicit user decision).** `rustls-rustcrypto` is
community-maintained and not audited to the bar of `aws-lc-rs`/`ring`, so this
deviates from §19's "reviewed TLS library" preference. The maintainer chose it
to keep one auditable, pure-Rust crypto surface rather than introduce C for the
transport layer alone. If the provider proves unmaintained or insufficient
(e.g. a needed cipher suite, a soundness concern), switching to `aws-lc-rs`
behind the same `CryptoProvider` seam is the fallback, and this ADR is
superseded.

`rcgen` was not used for certificate generation: its default backends are the
C providers, which would reintroduce C. `x509-cert` + `ed25519-dalek` (via a
thin `SignatureBitStringEncoding`/signer wrapper) generates and self-signs the
certificate in pure Rust; the self-signature is verified in tests.

## Consequences

- Endpoint certificate generation is pure Rust and verified (parses,
  issuer==subject, self-signature checks out under the endpoint key). Closes
  the M3-deferred "self-issued X.509 endpoint certs" item.
- The rustls server/client wiring (mTLS, cert pinning, the §9.1 profile) lands
  in `axon-transport` (M5) on this provider.
- The provider choice is revisitable at the `CryptoProvider` seam without
  touching endpoint-cert generation or app-layer crypto.
- No golden vector: certificate bytes depend on wall-clock validity, so tests
  assert structural properties and self-signature validity, not frozen bytes.
