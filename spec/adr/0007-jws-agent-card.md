# ADR-0007: Minimal EdDSA JWS for Agent Card signatures

Status: accepted
Date: 2026-07-16

## Context

A2A signs the Agent Card with the standard `AgentCardSignature` mechanism —
an RFC 7515 JWS in flattened JSON serialization (`protected`, `signature`,
optional `header`). A2A spec §8.4 fixes the payload: remove default-valued
properties and the `signatures` field, canonicalize the remainder with RFC
8785 (JCS), base64url it; the signing input is
`BASE64URL(protected) "." BASE64URL(payload)`.

Design §10.1 narrows this to one mandatory v1 profile: a **separate Ed25519
key**, `alg: EdDSA`, `typ: JOSE`, and an RFC 7638 thumbprint `kid`. `none`,
symmetric peer-supplied keys, and unpinned remote key URLs (`jku`) are
forbidden; the verification key comes from pairing or a locally configured
trust domain and is never fetched. This is a single algorithm with a strict,
closed header shape — not algorithm agility.

Candidates: `josekit` (pulls OpenSSL, full JOSE algorithm matrix), `jsonwebtoken`
(pulls `ring`, many algorithms), or a minimal JWS built on the primitives we
already vendor (`ed25519-dalek`, `base64`, `serde_json`, `json-canon`).

## Decision

Implement a **minimal EdDSA JWS** in `akson-crypto::jws`, a thin frame over
`ed25519-dalek` (design §3.3: thin wrappers over reviewed libraries). It signs
and verifies exactly one profile and rejects everything else:

- Header is a closed struct `{alg, typ, kid}`, serialized canonically (JCS) so
  its bytes are reproducible; any other member, or `alg != "EdDSA"`,
  `typ != "JOSE"`, or a missing `kid`, fails closed.
- The payload is opaque bytes supplied by the caller (already canonical); the
  primitive never re-serializes it. `kid` **must** equal the RFC 7638
  thumbprint recomputed from the pinned verification key — a signature can
  never present key A under thumbprint B (the DSSE keyid discipline, ADR-0004).
- Verification uses `verify_strict` (rejects low-order keys and non-canonical
  `R`). Detached, flattened JSON serialization only: `protected` + `signature`
  strings drop straight into `AgentCardSignature`.

The Agent-Card-specific mapping (serialize the card via the proto3 JSON
mapping, drop `signatures`, JCS to payload bytes) lives one layer up in
`akson-proto::card_sig`, beside the structural card validator. `none`,
symmetric, `RS*`/`ES*`/`HS*`, and any `jku`/`x5u`/`x5c` member are rejected
before signature math. No key URL is ever dereferenced.

A general JOSE library is rejected for v1: its value is algorithm agility,
which is pure attack surface (alg-confusion) for a one-algorithm mandatory
profile, and it enlarges the audited dependency set. Additional managed
algorithms remain possible later as an additive negotiated profile with its
own vectors (design §14.2), not a change to this default.

## Consequences

- The signed-card path stays pure Rust with no OpenSSL/`ring`, and the whole
  JWS surface is a few hundred fully-vectored lines.
- Golden vectors `spec/vectors/jws/` freeze the canonical header bytes, the
  JCS payload, the signing input, and the (deterministic, RFC 8032) signature;
  `xcheck/` reproduces them with `rfc8785` + `cryptography`.
- Closes the tracked Codex finding H6: `akson-proto::card_sig::verify_card`
  performs signature verification (the pinned key comes from pairing, M6).
- Any future non-EdDSA card algorithm requires a new ADR and vectors; the
  header allowlist is the single enforcement point.
