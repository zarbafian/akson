# ADR-0015: The introduction protocol

Status: proposed
Date: 2026-07-23

## Context

Identity-token pairing (design/2026-07-23-identity-token-pairing.md §3)
replaces the invitation bootstrap (§8.2 steps 1–7) with a first-contact
**introduction**: both operators have already imported each other's root
commitment (ADR-0013), so first contact is mutual verification, not
negotiation. The design fixes the properties — responder-proves-first
disclosure, a cheap pre-crypto admission gate, TLS-session binding, epoch
compare-and-swap, one introduction per connection — and defers the exact
wire contract to this ADR.

Constraints inherited from the review of the design draft: the dialer must
disclose nothing before the responder proves the imported root (MITM/hijack
harvest); unknown callers must be refused before any signature work (DoS);
RFC 9266 channel bindings identify a TLS connection and permit one
authentication instance per connection; the existing receive listener
discards source addresses, has no limiter, routes everything to the A2A
handler, and the pinned-cert send path must not be loosened.

## Decision

### Route and framing

- Two operations on the **receive listener**, matched by path *before* the
  A2A peer resolver: `POST /akson/introduce/v1/hello` and
  `POST /akson/introduce/v1/complete`. Media type
  `application/vnd.akson-dev.introduction.v1+json`; body cap **64 KiB** per
  request (vs. 1 MiB for A2A); per-source-address token-bucket rate limit
  (the listener starts retaining the accepted socket address).
- Both requests MUST arrive on the **same TLS connection**; the responder
  keeps one pending introduction per connection (nonce, exporter), and the
  transcript embeds the exporter, so a reconnect cannot mix flights. After
  the `complete` response, both sides MUST close the connection (RFC 9266
  one-instance rule); work traffic uses a fresh connection under the newly
  pinned certificate through the unchanged fast path.
- TLS: both sides present certificates and provisionally accept the peer's
  (a dedicated introduction client and server verifier — the ordinary
  pinned-cert paths are not relaxed). Errors outside verification use RFC
  9457 problem details.

### Flights

1. **hello** (dialer → responder): `{versions, target_root, claimed_root,
   nonce}` — protocol version, token version, the imported target
   thumbprint, the dialer's own thumbprint, 32 random bytes. No keys, no
   card. The responder's admission gate, before any signature work:
   `claimed_root` is imported, its epoch live, `target_root` is me,
   versions supported. Any failure → one uniform generic refusal
   (`introduction-refused`, no detail), constant-time membership lookup.
2. **hello response** (responder proves first): the responder's key-binding
   record, signed extended Agent Card, and proof-of-possession signatures
   over the transcript (below). The dialer verifies — root equals the
   imported commitment, card JWS under that root, `validate_agent_card`
   profile validation, the record's TLS certificate byte-equal to this
   connection's, PoP for every advertised key — and only then discloses.
3. **complete** (dialer proves): the dialer's equivalent material and
   proofs. The responder runs the same checks, binding the dialer's root to
   the `claimed_root` of flight 1.
4. **complete response** (ack): the responder persists the full §8.1 tuple
   by compare-and-swap on `(root_thumbprint, epoch)` and acknowledges; the
   dialer commits on receiving the ack. Close.

### Transcript

The bytes every proof signs are **exactly the RFC 8785 canonical JSON** of
the object below — the domain string is a field inside it, so there is one
canonicalization and nothing else for a second implementation to agree on:

```json
{ "domain": "akson-introduction-v1",
  "protocol_version": 1,
  "token_version": 1,
  "role": "dialer" | "responder",
  "dialer_root": "<thumbprint>",  "responder_root": "<thumbprint>",
  "dialer_tls_sha256": "<hex>",   "responder_tls_sha256": "<hex>",
  "tls_exporter": "<b64url, RFC 9266 EXPORTER-Channel-Binding, 32 bytes>",
  "nonce": "<b64url>",
  "key_binding_sha256": "<hex, of the signer's canonical record>" }
```

Both roots, both certificates, the live TLS session, and the token/protocol
versions are therefore all under every signature: a proof cannot be replayed
into another connection, another pairing, or a downgraded parse. Plumbing
the exporter out of the TLS layer into this handler is a new API in both
transports (client and server) — named here because it is cross-layer work,
not a local edit to `verify_accepter` (whose check sequence is otherwise
kept, with the root-commitment equality and profile validation added).

### State and errors

- Commit is CAS on `(root, epoch)`: an epoch bumped by `peer remove` fails
  the commit (no resurrection); a divergent concurrent introduction fails
  it; for an already-`active` peer, changed material suspends per §8.4
  rather than re-pins; identical material is an idempotent no-op (crash
  between the two commits heals on the next introduction in either
  direction).
- Error matrix (normative): every pre-verification failure at the responder
  — not imported, tombstoned, wrong target, bad version, rate-limited,
  malformed — maps to the single generic `introduction-refused` with no
  distinguishing detail or timing. Post-proof failures (bad card, PoP
  mismatch, CAS conflict) MAY carry specific problem types: at that point
  the parties are mutually authenticated. The dialer's CLI accordingly
  reports generic refusals as a *likely-causes list* (not-imported-yet
  first, with the actionable fix), never as an asserted single cause.
- Refusals leave a local **knock log** on the responder: `(claimed root,
  source address, refusal class, time)`, rate-limited and deduped at write,
  queryable via `akson peer knocks`, never pushed to hooks. It exists to
  debug the "we both think we added each other" case; because hello claims
  are unauthenticated, entries are labeled *claimed*, and the log carries no
  authority.
- The responder's card is disclosed to any caller whose hello names an
  imported thumbprint (flight 2 precedes dialer proof — someone must go
  first, and responder-first is what protects the dialer from hijacked
  endpoints). Card disclosure is therefore bounded by the secrecy of the
  relationship graph; the threat model carries this residual explicitly.

## Consequences

- `AKSON_PAIR_ADDR`, the bootstrap listener, invitation secrets, the replay
  ledger, and `pair invite|accept` + `peer confirm` are removed; the
  introduction is the only first-contact surface and costs unknown callers
  one table lookup. Fallout sweep: `whoami`/control-protocol shapes, daemon
  startup output, harness runner imports, `bench/`, README and guide.
- The model checker replaces the invitation state machine with
  import/introduction/epoch and proves: no admission without import, no
  commit across an epoch bump, no divergent double commit, and the
  disclosure order (dialer material only after responder verification).
- Golden vectors: transcript canonical bytes + PAE for both roles; a hello
  and both proof bodies; refusal shapes. Conformance: a second
  implementation must interoperate against the vectors and the live
  handshake (§3.1 condition 7).
- Test surface: unit (gate ordering, CAS/epoch races, mixed-connection
  flights refused), e2e (fresh pair over loopback: import ×2 → first
  `task send` triggers introduction → task flows on a second connection),
  fuzz (hello and proof parsers, 64 KiB cap).
