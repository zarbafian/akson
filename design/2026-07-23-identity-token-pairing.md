# Identity-token pairing

Status: draft v3. v2 was revised after a three-scope adversarial review
(protocol security, tree consistency, completeness); v3 records the
maintainer decisions of 2026-07-23 — key-only token container, interim root
custody, auto-activation, manual endpoint updates — now carried by
ADR-0013/0014/0015 (proposed). Addresses the pairing section of #5
(multi-step manual dance) and the structural cause of #2 (self-declared
names collide). Amends design §8.2 (personal pairing); §8.1 (identity tuple)
and §8.4 (rotation and suspension) are unchanged except where noted.

## 0. In one look

Each endpoint has one public **identity token** — printable, QR-able text.
Two people exchange tokens over any channel they already trust, and each
imports the other's, choosing a **local label** at that moment:

~~~text
alice$ akson token
  akson1q9x…k7w@198.51.100.7:18443        # + QR on a tty

bob$   akson peer add akson1q9x…k7w@198.51.100.7:18443 alice
alice$ akson peer add akson1z3m…p2q@203.0.113.9:18444 bob-codex

alice$ akson task send /tmp/task.json     # performer: "bob-codex"
~~~

That is the whole pairing. No invitation file, no file shuttle, no `pair
accept`, no `peer confirm`. The import **is** the human yes; the label is
chosen by the receiving operator, never by the peer.

Two ideas carry it:

1. **The token is an address, not a secret.** It grants nothing by
   possession, so the out-of-band exchange needs integrity, not
   confidentiality. The enforced property is per-side: *your daemon admits an
   introduction only from a root key you imported.* When both operators
   import each other — the honest-peer picture — the channel comes up;
   the one-sided property is what the daemon can actually enforce, and is
   what the model checker will state (a malicious dialer can always *claim*
   it imported you; it cannot make you admit it).
2. **Names are local.** The peer's handle everywhere local (task specs at the
   CLI, `peer list`, auto-approve, audit display) is the label the *local*
   operator assigned at import. What a peer calls itself is display
   metadata; on the wire, relationships are identified by root-key
   thumbprint (§5).

## 1. The token

### 1.1 Contents

~~~text
token     = bech32m("akson", version ‖ root key)      65 chars, conforming
version   1 byte    format + suite (Ed25519, SHA-256); unknown ⇒ refuse at entry
root key  32 bytes  the endpoint's identity root public key

presented as   <token>[@host:port]
~~~

**Decided (ADR-0013): the token is key-only.** The routing hint rides
*outside* the checksummed token, as an optional `@host:port` suffix the CLI
splits off (scheme https and the introduction path are implied, never
encoded). This keeps the token inside bech32m's 90-character validity bound,
and the encoding honestly mirrors the trust split of §1.1: what the checksum
protects is exactly what the operator is trusting (the key); the suffix is
the unauthenticated hint it claims to be.

The **identity root key** is the agent-card JWS key of §8.1 — the key that
signs the extended Agent Card. The token commits to it by value (a 32-byte
Ed25519 key is no larger than its hash). Everything else about the peer —
TLS certificate, task-statement and evidence keys, purposes, generations —
arrives at introduction inside a card *signed by this key* and is verified
against this commitment, including the A2A profile validation the card must
already pass today (`validate_agent_card`; a root-signed card that
advertises a non-mTLS or malformed interface is refused, not pinned).

Two consequences, stated plainly rather than rounded away:

- **The root key becomes a single long-lived impersonation point.** Today,
  becoming someone's peer before first contact requires the invitation
  bearer secret *and* card-key material, and the invitation also pins the
  inviter's TLS certificate independently. Under this design, theft of the
  root private key alone lets an attacker introduce itself as that identity
  (minting fresh subkeys and a fresh TLS certificate) to anyone holding the
  token. This is the standard trade of every identity-key system (SSH host
  keys, Signal identity keys), but it concentrates what §8.2 splits.
  **Decided:** v1 ships with the existing interim sealed file custody — the
  same posture as every other key today — the threat model gains this entry,
  and hardened custody (keyring/hardware/passphrase) is follow-on work, not
  a blocker.
- **The endpoint is an unauthenticated hint.** A wrong or hijacked address
  cannot yield a wrong identity — the introduction fails root verification —
  and, by the disclosure ordering in §3, a hijacked endpoint also cannot
  harvest the dialer's identity material. The `@host:port` suffix or
  `peer add … --endpoint host:port` supplies it; re-running `peer add` with
  the same root and `--update` refreshes hint or label (it never changes
  trust state). **Decided: hints are manually updated only in v1** — a moved
  peer re-shares its hint and the operator runs `--update`; card-driven
  address changes are out of scope (no freshness/rollback machinery).

One root key belongs to one daemon endpoint instance. Shared-root
high-availability topologies are explicitly out of scope for v1.

### 1.2 Encoding — decided, ADR-0013

The normative design's standards-first rule names identity tokens explicitly
(§3: "must not create a new … identity token … when a suitable established
format exists"), so the container is an ADR-governed choice under §3.1's
seven conditions. ADR-0013 records it: **key-only bech32m** (HRP `akson`,
1-byte version + 32-byte root key, 65 characters, lowercase canonical), with
the endpoint as an unprotected `@host:port` presentation suffix. In short:

- Established containers were evaluated and fail the entry-time bar:
  did:key/multibase is case-sensitive base58btc with *no* checksum (a typo is
  a different plausible key — the c2c failure mode, Appendix B); SSH/JWK
  encodings likewise. age's `age1…` recipients are the direct precedent for
  bech32 key distribution; BIP-350's bech32m fixes bech32's known checksum
  weakness.
- bech32m's guarantees hold only to 90 characters, which an embedded
  endpoint blows past (Appendix A) — the 90-char cap and the trust split
  both argue for keeping the hint outside the checksum.

The token version byte is covered by the introduction transcript (§3), so a
checksum-valid rewrite of the version cannot survive verification.

## 2. Import and the local label

~~~text
akson peer add <token> <label> [--endpoint host:port] [--update]
akson peer label <old-label> <new-label>    # rename any time, purely local
akson peer remove <label>                   # tombstones the relationship
~~~

`peer add` is the trust decision and the only ceremony. It:

1. checksum-decodes the token; refuses on any error, including an unknown
   version byte;
2. requires `<label>`: 1–64 chars of `[a-z0-9-]`, no leading/trailing or
   doubled hyphen, locally unique. There is no default — the operator names
   the relationship. Collisions are a local rename problem, never a security
   event;
3. stores a **provisional import record** keyed by the root-key thumbprint
   (RFC 7638): label, endpoint hint, epoch, added-at. This is *not* a peer
   row — the §8.1 identity tuple (TLS certificate, subkeys, card digests)
   does not exist yet and the current `peers` schema requires it; the full
   row is created only when an introduction commits (§3).

The label never crosses the wire: alice never learns bob filed her under
`sketchy-alice`. The CLI resolves label → thumbprint at send and renders
thumbprint → label on display; resolution happens once, at task creation —
retries and audit records hold the thumbprint, and a later rename changes
display only. Two peers who both self-declare `me/claude` now *coexist* as
`dana-claude` and `sam-claude`. (Today they cannot: the pairing path refuses
a same-name different-identity peer outright — `store_pending_peer`'s
`detect_change` guard — so the collision is exclusion, not hijack. Re-keying
turns refusal into coexistence.)

Peer states are `imported` (provisional record, no verified contact),
`active` (introduction committed), and `suspended` — §8.4's suspension on
unexpected identity change is kept exactly as is: a root-signed card that
*changes* pinned material after activation suspends the peer for operator
review; it never silently re-pins.

**Removal and re-add are epoch-bounded.** `peer remove` writes a tombstone
and bumps the relationship epoch in the same transaction; an introduction
that commits its state must compare-and-swap against the epoch it started
from, so a handshake racing a removal fails to commit rather than resurrect
the peer. Re-adding the same root later starts a new epoch: fresh
introduction required, nothing cached restored, and traffic signed under the
old epoch is refused. In-flight work at removal time is cancelled with a
signed refusal, mirroring `task deny`.

**What import does *not* approve.** The operator imports a key and an
address; the issuer-qualified display tuple, security projection, and subkeys
arrive only at introduction and activate without a second prompt. That is
deliberate — this design exists to remove the second yes — and it is safe
for the same reason arrival is: activation only lets tasks *arrive* (inert)
and lets your own sends reach the intended root. Every consequential decision
(`task approve`, a processor grant) happens later, with the verified
issuer/agent tuple and root thumbprint on the risk card in front of the
human. §8.4 suspension covers post-activation changes.

## 3. First contact: the introduction

The channel comes up lazily, on the first connection in either direction
(first `task send`, or an explicit `akson peer ping <label>`). Both sides
hold the other's root commitment before any bytes flow, so the introduction
is mutual verification with a fixed disclosure order — the party whose
authenticity the dialer can already check goes first:

1. **Connect.** The dialer opens TLS to the imported endpoint hint on the
   receive listener's introduction route (a distinct path, matched before
   the A2A handler, with its own small body cap and a source-address rate
   limiter — the listener must retain the peer address it currently
   discards). Certificates are provisionally accepted on both sides; neither
   is resolvable yet.
2. **Hello (dialer).** Protocol version, token version, the *target* root
   thumbprint (from the imported token), the dialer's *claimed* root
   thumbprint, and a nonce. No card, no keys. The responder performs a cheap
   membership check — claimed thumbprint imported, epoch live, target is me
   — and on any failure returns one generic refusal *before any signature
   work*. This is the anti-DoS gate that replaces the invitation secret:
   unknown callers cost a table lookup, not JWS verification.
3. **Responder proves first.** The responder sends its key-binding record,
   signed extended card, and proof-of-possession signatures over the
   introduction transcript. The dialer verifies: root key equals the
   imported commitment; card signature under that root; card passes
   `validate_agent_card`; the record's TLS certificate is byte-equal to the
   one on this connection; PoP for every advertised key. Only after all of
   that does the dialer disclose anything — so a hijacked endpoint or MITM
   without the root key harvests nothing from the dialer.
4. **Dialer discloses and proves.** Same material, same checks on the
   responder side, now binding the *claimed* thumbprint of step 2: the
   dialer's root must equal what it claimed and what the responder imported.
5. **Commit, ack, close.** The responder persists the full §8.1 tuple under
   (root thumbprint, epoch) by compare-and-swap and sends a final
   acknowledgement; the dialer commits on receiving it. A CAS conflict —
   concurrent introduction with different material, or an epoch bumped by
   removal — refuses and, for an already-active peer, suspends per §8.4
   rather than overwrite. The connection is then **closed**: RFC 9266
   permits one authentication instance per connection, so the triggering
   task is sent on a fresh connection under the newly pinned certificate,
   through today's unchanged fast path.

The **introduction transcript** — the bytes every PoP signs — is frozen by
the protocol ADR (§6.1) and must cover at minimum: a domain-separation
string, protocol and token versions, both roles, both root thumbprints, both
TLS certificate digests, the RFC 9266 `tls-exporter` value of this
connection, the nonce, and the canonical key-binding digest. Naming the
exporter alone is not a transcript; and plumbing it out of the TLS layer
into the handler is a new cross-layer API in both transports, not a local
substitution in `verify_accepter`.

What each party learns, honestly: an unimported scanner gets a generic
refusal after step 2 — but a scanner that knows *both* your token and the
thumbprint of someone you imported (neither is secret) receives your card in
step 3 without proving anything. Card disclosure is bounded by the secrecy
of the relationship graph, not by a proof. This is narrower than today's
open bootstrap listener during a live invitation, but it is not "no
disclosure", and the threat model should carry it. Symmetrically, the
dialer's refusal diagnostics are honest about ambiguity: a generic refusal
is indistinguishable from wrong-address, version mismatch, rate limiting, or
not-imported — the CLI lists the likely causes and the one actionable fix
("if they haven't added you: they need `akson peer add <your token>`"),
never asserts one.

Simultaneous dials from both sides are legal; both introductions verify the
same material and the CAS makes the second commit a no-op. A crash between
the two commits leaves one side `active` and one `imported`; the next
connection in either direction simply runs the introduction again — it is
idempotent over identical material.

## 4. Security analysis

What each attack costs, compared with §8.2 invitation pairing:

| Attack | Today (invitation) | With identity tokens |
| --- | --- | --- |
| OOB channel *eavesdropped* | Finder becomes the pending peer (bearer secret) | Nothing — token is public |
| OOB channel *substituted* | Attacker pairs in place of peer | Same class: attacker's token imported in place of peer's (§4.1) |
| Token/invite *replayed* | Single-use verifier + replay ledger | Nothing to replay; introduction is bound to its TLS session via the exporter transcript |
| Endpoint address hijacked (DNS/IP) | Bootstrap connects to the attacker but fails the invitation's pinned inviter certificate | Introduction reaches the attacker, who cannot prove the root key; by §3 ordering the dialer has disclosed nothing yet |
| Unsolicited pairing / spam | Bootstrap listener is open (though invitation-gated and rate-limited) while an invite is live | No bearer-secret surface at all; the introduction route is always present but costs unknown callers one table lookup before refusal |
| Unknown scanner probes the port | Learns a TLS server exists | Same; with your token *and* an imported peer's thumbprint, also your card (§3) — relationship-graph bounded |
| Identity-key compromise | Invitation secret + card material needed pre-contact; TLS cert pinned independently | **Worse in one axis:** root private key alone impersonates the identity to token holders (§1.1); v1 ships on interim custody, named in the threat model |
| Sub-key (TLS cert) rotation | Re-pair (§8.4 personal v1) | Unchanged in v1: a changed cert suspends for review (§8.4). Root-signed in-place rotation is a possible relaxation, own ADR (§6.2) |

### 4.1 The residual, stated plainly

Whoever can substitute content in the out-of-band channel can substitute the
token, exactly as they could substitute an invitation file today. The
mitigation is unchanged: exchange the token over a channel you'd accept a
yes from — in person via QR, or verify the displayed root-key fingerprint
over a second channel (`akson peer show <label>` prints it full-length;
§8.1's no-truncation rule applies). Two things *narrow* against today: the
OOB requirement drops from *integrity and confidentiality, before expiry,
single-use* to *integrity, once*; and one review barrier is *removed* —
§8.2's pending state showed the verified full identity before a distinct
confirmation, whereas here activation is automatic and the verified tuple is
first shown on the risk card at `task approve` (§2 argues why that is the
right gate; it is still a change worth naming).

### 4.2 Invariants

- **Arrival is not execution** (§6.3) gains a sibling the checker can state:
  *no admission without import* — an endpoint never creates peer state, nor
  advances past the §3 membership gate, for a root its operator has not
  imported. (The two-sided "both imported" picture is honest-peer behavior,
  not an invariant — see §0.)
- **Identity is issuer-qualified** (§6.3): the contract's identity fields
  remain issuer-qualified and gain the root thumbprint as the stable
  relationship key (§5); the local label is presentation only, per §8.1.
- **Deny by default**: the secret-gated bootstrap listener and
  `AKSON_PAIR_ADDR` are deleted; what remains is one always-on route whose
  unauthenticated cost is a table lookup.

## 5. Plumbing

What this changes in the tree — none of it visible in §0. Pre-release
posture: this is a clean cut, no compatibility mode, no row migration.
Existing relationships are re-established by exchanging tokens; existing
`pending` rows are dropped (they represent a remote bootstrap that never
received the local yes — there is no faithful mapping onto `imported`, which
asserts exactly that yes); in-flight tasks drain or are cancelled before
upgrade. Signed artifacts produced under the old identity shape remain
verifiable as historical records but do not migrate forward.

- **Store.** New provisional-import table keyed by root thumbprint (label
  unique, endpoint hint, epoch, tombstones), plus the knock log (§6.1.7:
  refused-introduction records, rate-limited and deduped at write). `peers`
  re-keys by root thumbprint; `label` unique column; `status ∈ {imported,
  active, suspended:<reason>}`. `peer_keys` gains the root thumbprint as the
  relationship key (today it carries only the self-declared `agent_id`, and
  `remove_peer` deletes by that name — under coexisting same-named peers
  that would strip *both* peers' keys). `auto_approve` re-keys by root
  thumbprint for the same reason: today two same-named peers would share and
  overwrite one standing-authority row. The `detect_change` overwrite guard
  is retained under the new key, feeding §8.4 suspension.
- **Wire.** The contract's requester/performer identity gains the root
  thumbprint alongside the issuer-qualified tuple — a new contract schema
  revision (the current schema is reject-unknown, so this cannot be
  smuggled), with matching changes in approval, delivery, and outcome
  verification, which today compare `{issuer, agent}` exactly. Risk cards
  display the verified tuple plus root thumbprint, rendered under the local
  label. This is the #2 fix on the requester-display side.
- **Daemon.** `AKSON_PAIR_ADDR` and the bootstrap listener are removed — one
  of #5's seven env vars gone. The introduction route lives on the receive
  listener, which must retain source addresses, add a limiter and a small
  introduction body cap, and route by path *before* the A2A peer resolver.
  A distinct introduction TLS client (provisional certificate acceptance) is
  required — the existing send path resolves a pinned certificate before it
  will connect at all and must not be loosened; sequencing is introduce →
  pin → re-resolve → send. The `tls-exporter` value is plumbed from both
  transports into the introduction handler (new API). Removal fallout to
  sweep: `whoami`/control-protocol shapes, daemon startup output, the
  harness runner's invitation imports, `bench/` scripts, README and guide.
- **Kept.** `verify_accepter`'s check sequence (with the root-commitment
  equality and profile validation added), key-binding verification,
  proof-of-possession, the sealed-store discipline, and the receive fast
  path once a certificate is pinned.
- **Spec.** §8.2 rewritten to this flow; `spec/control-protocol.md` gains
  the new peer verbs and loses the pair verbs; the checker replaces the
  invitation state machine with import/introduction/epoch and proves: no
  admission without import, no commit across an epoch bump, no second
  divergent commit, and the §3 disclosure order.

## 6. Decisions and open questions

### 6.1 Decided 2026-07-23 (maintainer)

1. **Token container** → key-only bech32m with `@host:port` presentation
   suffix — **ADR-0013** (proposed).
2. **Contract identity revision** → root thumbprint alongside the
   issuer-qualified tuple, payload versions bumped in lockstep —
   **ADR-0014** (proposed).
3. **Introduction protocol** → route, flights, frozen transcript, error
   semantics — **ADR-0015** (proposed).
4. **Root-key custody** → ship v1 on the existing interim sealed custody;
   threat-model entry added; hardening is follow-on work (§1.1).
5. **Endpoint authority** → manual updates only in v1 (`peer add --update`
   after an out-of-band re-share); no card-driven address changes (§1.1).
6. **Auto-activation** → accepted; the reviewed identity is first shown at
   `task approve` (§2, §4.1). Lands in the normative §8.2 rewrite.
7. **Knock visibility** → a queryable knock log: refusals at the admission
   gate are recorded locally (claimed root, source, time; rate-limited and
   deduped) and surfaced only by `akson peer knocks` — never pushed to
   hooks, so a stranger holding your token cannot make anything ping.
8. **Voice fallback** → closed for v1: the 65-char token is dictatable at a
   stretch, and §4.1's second-channel fingerprint comparison covers
   uncertain channels. (PAKE short codes stay out of scope per §8.2 unless
   standardized.)

### 6.2 Still open

9. **Sub-key rotation without re-pairing.** A root-signed card rotating the
   TLS cert in place would relax §8.4 with better UX; strictly an ADR
   against §8.4, deferred.

## Appendix A — what a token looks like

Real encodings (actual checksummed output, stand-in key), for size honesty.

~~~text
the token (33-byte payload: 0x01 ‖ 32-byte root key)
  akson1qxvn3q9es7xskfw94vvm2klpmnnlvjhpcjzwjgvx4nvdk4fsx6wp2madn9y
  65 chars — conforming bech32m (ADR-0013)

as presented, with the unprotected hint suffix
  akson1qxvn3q9es7xskfw94vvm2klpmnnlvjhpcjzwjgvx4nvdk4fsx6wp2madn9y@198.51.100.7:18444
  the CLI splits at '@'; the suffix is outside the checksum by design

REJECTED for the record — endpoint inside the payload (v2 review finding):
  51-byte payload → 94 chars, 58-byte → 105 chars: both exceed the
  BIP-173/350 90-char validity bound, past which the guaranteed
  error-detection bounds no longer hold.
~~~

Base58check equivalents run ~74/84/50 characters — shorter, but
case-sensitive (QR byte mode → larger codes), checksum-only error
*detection* with no localization, and no formal spec (§1.2).

What `akson token` prints on a tty:

~~~text
$ akson token
  identity  orgB/bob                    (display only — peers will label you themselves)
  root key  sha256:820fd6a2…27e1d1b0    (full digest shown; §8.1 no-truncation rule)

  akson1qxvn3q9es7xskfw94vvm2klpmnnlvjhpcjzwjgvx4nvdk4fsx6wp2madn9y@198.51.100.7:18444

  █▀▀▀▀▀█ ▀ █▄█ ▄▀ █▀▀▀▀▀█     scan, or send the line above over any
  █ ███ █ ▄▀▀▄▀██▄ █ ███ █     channel you trust the integrity of —
  █ ▀▀▀ █ █▄▀ ▀▄ ▀ █ ▀▀▀ █     the token is public, not secret
  ▀▀▀▀▀▀▀ ▀ ▀ ▀ ▀ ▀▀▀▀▀▀▀
~~~

## Appendix B — prior art: c2c

c2c (local-first agent messaging, sibling project) solved adjacent problems
with different trade-offs; three of its choices informed this draft, two are
deliberately not taken:

**Confirms the model.** c2c gates private relay rooms by inviting an Ed25519
*identity public key*, explicitly not an alias ("aliases are TOFU-pinned but
not secret") — the key-is-the-invite idea, arrived at independently. It also
separates the routing identifier (`host_id`, an opaque 12-hex id) from the
identity key, as this draft separates the endpoint hint from the root key.

**Encoding lesson.** c2c exchanges the raw public key as 43 chars of
base64url-nopad (`--invitee-pk`). That is shorter than any framed token but
has no checksum, no version byte, and is case-sensitive: a misread character
produces a plausible-looking wrong key that fails only later — or, under
TOFU, silently pins the wrong identity. The token's version byte + checksum
requirement exists to make that failure impossible at entry time.

**Not taken: TOFU.** c2c pins alias→key at first signed registration
(first-come at a shared relay), with optional `--allowed-identities`
hardening. Akson's model has no first-use leap of faith: commitment travels
out-of-band *before* contact, and an unknown key is refused rather than
pinned. This is the trust-model line between a messaging broker and a system
that executes work.

**Not taken: the relay.** c2c routes through a shared relay
(alias-registration races, PoW anti-spam, E2E as an upgrade with plaintext
fallback for unkeyed peers). Akson stays direct mTLS with no fallback tier —
the §1 product principles already commit to that; the c2c experience shows
what the relay costs in identity complexity once one exists.
