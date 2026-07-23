# ADR-0013: Identity-token container — key-only bech32m

Status: proposed
Date: 2026-07-23

## Context

Identity-token pairing (design/2026-07-23-identity-token-pairing.md) replaces
invitation-file pairing with a public, shareable identity token: each endpoint
prints one, two operators exchange them out of band, and `akson peer add
<token> <label>` is the whole trust ceremony. Design §3 names "identity token"
among the formats Akson must not invent when a suitable established format
exists, so the container is governed by §3.1.

The unmet requirement (§3.1 condition 1): a text container for a 32-byte
Ed25519 public key that is **error-detecting at entry time with error
localization**, **case-insensitive** (QR alphanumeric mode), **versioned**,
and small enough for a small QR code and a terminal line. The token is public
by design — it is an identity commitment, not a bearer credential — so the
container needs integrity affordances only, no confidentiality.

Evaluated (§3.1 condition 2):

- **did:key (W3C) / multibase-multicodec**: established and key-typed, but
  the `z` base58btc encoding has **no checksum at all** and is
  case-sensitive. A single misread character yields a different
  plausible-looking key that fails only at first verification — the exact
  failure mode observed in c2c's raw-key exchange (design draft, Appendix B).
  Fails the entry-time requirement.
- **Raw base64url / JWK / SSH public-key text**: no checksum, case-sensitive,
  not QR-alphanumeric. Same failure.
- **base58check**: checksummed, but detection-only (no error localization),
  case-sensitive, and a de facto convention rather than a spec.
- **bech32 (BIP-173) / bech32m (BIP-350)**: purpose-built for hand-carried
  key material — guaranteed detection of up to 4 character errors with
  localization for display, case-insensitive, published and widely reviewed,
  with prior art for exactly this use in age's `age1…` recipient encoding.
  bech32m fixes bech32's known checksum weakness (BIP-350). Its guarantees
  hold only to **90 characters total**, which a 33-byte payload satisfies
  (65 chars) and an embedded endpoint does not (94–105 chars in the design
  draft's measured examples).

The endpoint question forced the shape: a token that also carries the routing
hint cannot be conforming bech32m. The maintainer decision (2026-07-23) is
that the hint does not belong inside the checksum anyway — the key is what
the operator trusts; the address is an unauthenticated hint the introduction
protocol treats as untrusted (ADR-0015).

## Decision

The Akson identity token is **bech32m** with:

- **HRP**: `akson`
- **Payload**: `version (1 byte) ‖ root_public_key (32 bytes)` — 65
  characters total.
- **Version `0x01`**: Ed25519 root key, RFC 7638 thumbprints, SHA-256
  digests. An unknown version byte MUST be refused at decode, before any
  storage or network activity. The version byte is additionally covered by
  the introduction transcript (ADR-0015), so a checksum-valid rewrite cannot
  survive verification.
- **Canonical form**: lowercase. Emitters MUST produce lowercase; decoders
  MUST accept all-lowercase or all-uppercase and MUST reject mixed case
  (standard bech32 rule). Decoders MUST reject strings over 90 characters.

**Presentation form**: `<token>[@host:port]`. The optional suffix is the
routing hint; the CLI splits at the last `@` and stores the parts
separately. The suffix is **outside the checksum by design** — its
integrity is deliberately not claimed, mirroring its unauthenticated status
in the introduction protocol. Scheme (`https`) and the introduction path are
implied and never encoded. QR output encodes the full presentation form in
byte mode (`@` is not in the QR alphanumeric set); a key-only token may use
alphanumeric mode uppercased.

`akson token` prints the presentation form (with hint, when the daemon knows
its advertised address) plus the full root-key fingerprint per §8.1's
no-truncation rule.

## Consequences

- Pairing UX is one line: the token survives voice, chat, QR, and a badge;
  a typo is caught and localized at `peer add` time, never later.
- The token is stable for the lifetime of the root key: sub-key rotation,
  certificate changes, and address moves never reprint it. Address moves are
  conveyed by re-sharing the hint text and `peer add --update` (v1 decision:
  no card-driven address updates).
- A second implementation needs only a standard bech32m codec plus this
  HRP/payload profile (§3.1 condition 7: the CLI and the conformance harness
  are the two independent decoders).
- Golden vectors (§3.1 condition 5), to live in `spec/vectors/token/`:
  valid lowercase, valid uppercase, mixed-case (reject), bad checksum with
  one flipped character (reject, position reported), wrong HRP (reject),
  unknown version `0x02` (reject), over-length (reject), presentation form
  with and without suffix.
- Security review scope (§3.1 condition 6): parsing (strict bech32m, length
  and case rules), downgrade (version in transcript), replay (n/a — the
  token is a public commitment, not a credential), ambiguity (single suite
  per version byte), privacy (token deliberately carries no endpoint;
  the presentation suffix is optional and shareable separately).
- The HRP `akson` and the token profile enter the extension registry at
  Phase 0 alongside the media types (§3.1 condition 4).
