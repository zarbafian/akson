# ADR-0004: Ed25519 purpose-separated signing keys

Status: accepted
Date: 2026-07-16

## Context

Design §8.1 separates transport identity, Agent Card JWS, task-statement,
local-authority, and evidence-signing roles, and requires every verification
key to be bound to permitted purposes at pairing. §14.2 mandates Ed25519
(RFC 8032) with public JWKs identified by RFC 7638 thumbprints. The design
permits temporary key reuse in early implementations but requires its removal
before stable release.

## Decision

Separate Ed25519 keys per purpose from the first commit — no temporary
reuse. Purposes are a closed enum: `tls-endpoint` (X.509 key), `agent-card`
(JWS), `contract-proposal`, `contract-decision`, `task-result`, `evidence`,
`local-authority` (never leaves the endpoint). Signing goes through
`ed25519-dalek` v2 behind one thin `axon-crypto` API that takes a purpose and
refuses cross-purpose use; verification requires the pinned (key, purpose)
pair. Public keys serialize as JWKs (`kty: OKP`, `crv: Ed25519`); key IDs are
RFC 7638 thumbprints computed over the required members only. Local-authority
work-order integrity may use a keyed MAC instead of a signature where the
issuer and verifier are the same daemon (decided in M8).

## Consequences

- Pairing exchanges and pins one key per purpose (design §8.2 step 5); the
  identity tuple stores thumbprints per purpose.
- Golden vectors cover JWK serialization, thumbprints, and signatures, and
  are cross-checked by `xcheck/`.
- Adding a managed HSM algorithm later is an additive negotiated profile
  (design §14.2), not a change to this default.
