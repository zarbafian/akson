# ADR-0014: Contract identity carries the root-key thumbprint

Status: proposed
Date: 2026-07-23

## Context

Identity-token pairing (design/2026-07-23-identity-token-pairing.md) re-keys
peer relationships by the identity root key's RFC 7638 thumbprint and makes
the human-readable name a local, operator-assigned label that never crosses
the wire. Under it, two peers who both self-declare `me/claude` coexist.

The wire cannot express that today. A contract's requester and performer are
`{issuer, agent}` pairs; the schema is reject-unknown; and approval,
delivery, and outcome verification compare both fields exactly
(`crates/akson-contract/src/contract.rs`, `spec/ext/contract.v1.schema.json`,
`crates/aksond/src/delivery.rs`, `crates/aksond/src/outcome.rs`). With
coexisting same-named peers, `{issuer, agent}` no longer identifies a
relationship — and every store row keyed by it (`peer_keys`, `auto_approve`,
sent requests) inherits the ambiguity. Standing auto-approval keyed by a
self-declared name is the sharpest edge: two same-named peers would share
and overwrite one authority row.

§6.3's "identity is issuer-qualified" invariant must survive: a bare key
identifier is not enough; policy identity includes the issuer/trust domain
and the current bindings.

## Decision

Every signed extension payload that names a requester or performer gains a
required `root` field alongside the existing issuer-qualified pair:

```json
"performer": {
  "issuer": "orgB",
  "agent":  "bob",
  "root":   "kWp7…43-char RFC 7638 base64url thumbprint…"
}
```

- `root` is the RFC 7638 JWK thumbprint of the peer's identity root key (the
  agent-card key, per the pairing design §1.1) — the same representation the
  key-binding records already use.
- **Matching rule**: the relationship key is `root`. A receiver resolves the
  peer by root thumbprint; `issuer` and `agent` MUST then equal the values
  pinned in that peer's verified card, else the message is refused
  (`identity-mismatch`). The pair is thus authenticated display and §6.3
  qualification, never a lookup key.
- Affected payload types bump **in lockstep** to `v2` (contract, decision,
  and the result-manifest/outcome payloads that embed party identities):
  `application/vnd.akson-dev.contract.v2+json`, etc. The DSSE envelope media
  type (ADR-0012) is unchanged. Schemas remain reject-unknown; `root` is
  required — there is no dual-shape window.
- Pre-release clean cut (design draft §5): v1 payloads are not accepted on
  the wire after the upgrade. Stored v1 artifacts remain verifiable as
  historical records under their original schemas.
- Local authority state re-keys accordingly: `auto_approve`, `peer_keys`
  relationship linkage, and sent-request matching move to the root
  thumbprint. The CLI resolves label → root at task creation, once;
  retries and audit records carry the thumbprint.

## Consequences

- The requester-display problem (#2) closes end to end: risk cards show the
  local label, the authenticated `{issuer, agent}` claim, and the root
  thumbprint — and the identity that authorizes anything is the thumbprint.
- Standing authority cannot be inherited across identities: an
  auto-approve row names exactly one root, so a name collision can no
  longer share or overwrite policy.
- Contract validation gains one cheap check (root ↔ pinned tuple equality)
  and every identity comparison in approval/delivery/outcome switches its
  key — mechanical but broad; the conformance suite and xcheck vectors for
  contract/decision/outcome all regenerate at v2.
- Golden vectors: v2 valid; v2 with root/tuple mismatch (reject); v2 missing
  `root` (schema reject); v1 payload presented post-upgrade (reject at the
  payload-type dispatch).
- A second implementation interops by matching on `root` and refusing on
  tuple mismatch — no heuristics about display names.
