# ADR-0016 — The coordination surface (`akson_byom_exchange_v1`)

Status: proposed

Date: 2026-07-26

Relates to: [ADR-0012](0012-dsse-envelope-media-type.md) (payload typing),
[ADR-0015](0015-introduction-protocol.md) (first contact),
`design/2026-07-25-byom-exchange-coordination-surface.md` (the design note this
decides),
`design/a0-evidence.md` A0.5 (the identity graph).

## Context

A sibling system (byom, via kovee's driver) needs to stage outbound contracts,
dispatch them once a human has consented, and read coordination state. It must
**not** be able to reach the admin surface: byom's own design forbids it
holding akson admin authority, and the kovee+byom program's R0 review rejected
"a scoped token on the broad admin listener" as an adequate boundary.

Akson has two control sockets today (`spec/control-protocol.md`): **admin**
(authority-bearing) and **worker** (narrow, for the sandboxed adapter). Both
admit only the daemon's own UID via `SO_PEERCRED`, and `Surface::satisfies`
gives admin dominance over worker.

The question this ADR settles: how does a *different* local principal get a
bounded surface, and what exactly is on it?

## Decision

### 1. A third socket, admitted by a configured UID

`coord.sock`, alongside the existing two, bound **only** when
`AKSON_COORD_UID` names an allowed peer UID. Unset ⇒ the socket is not created
at all — the same "absent rather than guarded" posture ADR-0015 took when it
removed the bootstrap listener (an unmounted endpoint cannot be probed).

Admission: the connecting peer's `SO_PEERCRED` UID must equal the configured
UID, **or** the daemon's own UID (so the operator can diagnose the surface
without a second account). Everything else is refused before the request line
is read.

**Chosen: a named UID, not a group.** A group grants membership transitively
and is edited by tools far from akson; a single UID is checkable in one
comparison, appears verbatim in the unit file
(`deploy/akson-coord.service`'s `User=akson-coord`), and makes the boundary an
OS access domain that an operator can read off `ls -l`. The cost — one
identity per driver rather than a pool — is the property we want.

### 2. The registry is deny-by-absence, and asymmetric

| Op | On coord | Purpose |
|---|---|---|
| `coord_whoami` | yes | identity + protocol/feature versions |
| `peer_show` | yes | verified peer identity tuple + card claims |
| `stage` | yes | **inert, idempotent** staging of outbound bytes |
| `stage_show` | yes | staged contract status + digests |
| `dispatch` | yes | one-shot: consumes a consent receipt, dispatches |
| `task_status` | yes | verification status of a dispatched task |
| `events_read` | yes | durable cursored coordination events |
| `capability_evidence` | yes | `FederationCapabilityEvidence` per peer |
| *everything else* | **no** | `forbidden-surface` |

Absent by design and worth naming: no approve/deny of an inbound task, no
pairing, no peer import, no processor or credential operation, no
`task send`/`fulfill`/`deliver`, no configuration. A compromised driver can
stage inert bytes and burn consent receipts it was already given. It cannot
mint consent, reach a credential, or touch inbound authority.

**The asymmetry is deliberate:** admin may invoke coord ops (diagnostics), but
a coord connection can never invoke an admin op. So `Surface` gains `Coord`
with admin dominating it, and `Coord` dominating nothing.

### 3. Consent stays on admin

`dispatch` requires a consent receipt it cannot create. Minting one is an
admin operation (`stage consent <ref>`, CLI `akson stage consent`) that shows
the operator the risk card for the exact staged digest first. This is the
§5.2 explicit-decision invariant applied to the federation path: the outward
disclosure is never automatic, and never the driver's to authorize.

### 4. Staging is inert

`stage` writes bytes and returns a reference. It starts no model, mints no
authority, touches no workspace, invokes no tool, opens no socket — the §6.3
"arrival is not execution" invariant, applied to the outbound direction.
Idempotency is on the content digest: the same bytes yield the same reference
and no second record.

### 5. A coordination dispatch is not a contract, and gets its own envelope

*(Decided in C4 slice 3; supersedes the "the carrier waits" consequence below,
which is retained as the record of why.)*

§4 fixes what the operator's risk card and consent digest cover: a payload, a
recipient label, a `task_type`. Akson's closed contract schema cannot carry that
without contract terms — an objective, a deliverable, a deadline — the operator
never saw, and synthesising them would make the consent receipt authorize more
than was read. That is the one thing this surface exists to prevent, so the
contract schema is **not** reused and no terms are invented.

Instead, one new in-tree object through the front door design note D5 names:
`spec/ext/coord-dispatch.v1.schema.json`, carried as an A2A Part of media type
`application/vnd.akson-dev.coord-dispatch.v1+json` beside the raw payload Part,
over the same pinned mutual-TLS `SendMessage` POST every other peer-to-peer byte
in akson already uses. Its members, and why each is there:

| Member | Why |
|---|---|
| `task_type` | consented to; the byom-owned type, uninterpreted |
| `recipient_label` | consented to (the card names it), **and** one of the three preimages of `staged_digest` — without it the receiver could check the bytes but not the digest consent binds |
| `payload_sha256` | the payload, by the digest the receiver recomputes |
| `staged_digest` | the exact value the consent receipt binds |
| `consent_receipt` | the identity of the authorization; the id only, never the sealed body, and it confers nothing on the receiver |
| `recipient_root` | so a misrouted disclosure is refused even over a good channel |
| `sender_root` | so a claimed sender can never differ from the pinned one |
| `schema_version`, `protocol` | so a receiver refuses rather than guesses |

`additionalProperties` is **false**: a contract term cannot be added later
without changing this ADR and the vectors.

**The envelope is not signed.** Its authenticity is the channel's — mutual TLS
pinned to the peer record on both sides — and its integrity is the digest chain
above. Signing it would need a purpose key, and there is no key purpose for a
coordination dispatch; borrowing `contract-proposal` to sign a non-contract is
the one-key-one-role violation this codebase refuses elsewhere, and adding an
eighth paired purpose is a larger change than this decision earns. **The
residual is named rather than hidden: a coordination dispatch is authenticated,
not non-repudiable — a recipient cannot prove to a third party who sent it.** A
future ADR that needs that adds the purpose; nothing here forecloses it.

The receiver checks four things and answers one generic `422` otherwise (the
reason is recorded locally, never returned): `sender_root` equals the
transport-authenticated root, `recipient_root` equals its own, the payload bytes
hash to `payload_sha256`, and the §4 derivation reproduces `staged_digest`.
**Arrival is still not execution**: an admitted disclosure creates no Task, no
contract head, no work order, and nothing to approve. It is acknowledged, one
`dispatch_received` event is recorded, and the payload is **not retained** —
retaining it would require an inbound coordination op §2's registry deliberately
does not have. That remains open, and is the natural next decision.

**A refusal is a write a remote party causes, so it is bounded the same way an
admission is.** The reason is kept locally — an operator has to be able to tell a
tampered disclosure from a lost one — but the refusal is committed through the
same §9.2 idempotency record as an admitted dispatch, under its own response
class, and the `dispatch_refused` event is appended only on first sight. A peer
re-sending one refused dispatch therefore replays the same `422` and writes
nothing; what it can still make this endpoint store is one row per *distinct*
request, which is exactly what an accepted dispatch costs. The class travels with
the replay because the stored bytes alone do not say whether the first answer
admitted or refused, and replaying a refusal as `200` would tell the sender the
opposite of the decision on record.

### 6. Where the bytes are is a durable column

`coord_dispatches` gains `egress_state` (V23): `pending` — committed, no
acknowledgement, the schema **default**, so a crash between the commit and the
send is honest by construction rather than by remembering to write something;
`sent` — the pinned recipient echoed this exact staged digest, **terminal**;
`failed` — attempted and refused.

**Carriage is bounded, and a bounded carriage does not deny the surface.** Every
stage of the outbound POST has its own ceiling — name resolution, the TCP
connect, the TLS handshake, the request/response exchange — because a recipient
that accepts the connection and then stays silent would otherwise hold the
control-socket thread `dispatch` runs on, and with it every other operation on
this surface. Two things follow, and both are chosen rather than incidental.
*One:* a timed-out attempt is `failed`, not `sent` — nothing echoed the staged
digest, and this endpoint does not report bytes as having left when that is
unknown — and `failed` is retryable, so the timeout lands in a state the ordinary
retry resumes; `egress.detail` names the stage that timed out. There is
deliberately no fourth state for "attempted, outcome unknown": `sent` is the only
one that claims delivery, and everything short of it is re-attemptable, which is
precisely what the driver needs to know. *Two:* the control sockets serve
connections concurrently (bounded), so one slow carriage delays only itself —
the timeout bounds how long an attempt lasts, the concurrency bounds who waits
for it.

Recovery is the driver's retry, not a background sweeper: re-presenting the
**same** `execution_key` re-attempts carriage and spends nothing (the V22 primary
key resolves it as a retry before any compare-and-set runs), while a *different*
key on that receipt stays `409 consent-spent`. So one consent yields exactly one
dispatch record and at-least-once carriage of it, deduplicated at the recipient
by the dispatch receipt, which is the A2A Message id. `Store::unsent_dispatches`
makes the worklist readable rather than implied.

**A re-send is byte-identical.** The recipient's §9.2 idempotency covers the body
digest as well as the Message id, so at-least-once carriage only works if one
logical dispatch is one sequence of bytes: the A2A body is emitted as RFC 8785
canonical JSON. Serialising the request struct directly does not have that
property — an A2A `Part`'s `data` is a `HashMap`-backed `Struct` with no fixed
member order — and without it the retry above arrives as a *different* request
under the same Message id and is refused `409 conflict`, leaving a disclosure
that was in fact admitted recorded here as never delivered.

**Everything that decides "this cannot leave" runs before the spend.** A staging
whose recipient is unnamed, un-introduced, suspended, or has no usable https
endpoint is refused `409 unroutable-recipient`; a staging whose own members
cannot form a conforming §5 envelope is refused `500 bad-envelope`. Both leave
the consent receipt live. Burning a one-shot consent on a disclosure that
provably cannot leave would be the worst failure available to this surface, so it
is closed structurally by ordering — and *routing alone was not that ordering*,
because the routing guard never inspects the envelope.

The other half of the same closure is at `stage`: `task_type` and the recipient
label are admitted by the §5 envelope schema itself rather than by a rule written
out a second time, so "acceptable to stage" and "acceptable to send" have one
definition and cannot drift apart into a gap a driver falls through.

**A staging the ledger has dispatched cannot be consented again.**
`stage_consent` refuses `409 already-dispatched`, and the §5.2 risk card's claim
about what has already left this machine is read off that same ledger rather than
asserted. An unconsumed receipt is not the only reason to refuse: consenting a
second time could only authorize a second disclosure of the same staged digest,
`coord_dispatches` resolves a `stage_ref` to a single row (so a second row would
make `task_status` ambiguous about which disclosure it describes), and the
recovery an operator wants for an unacknowledged carriage is the driver's retry
under the same `execution_key` — which the refusal's `detail` names.

## Threat cases

| Threat | Outcome |
|---|---|
| the driver is compromised and tries to approve an inbound task | the op does not exist on coord → `forbidden-surface`; it is not merely unauthorized, it is unaddressable |
| …tries to mint its own consent | consent is admin-only; a coord connection cannot reach it |
| …tries to dispatch bytes a human never saw | `dispatch` requires a receipt bound to the exact staged digest |
| …replays a spent receipt | one-shot: the receipt is consumed atomically with the dispatch |
| …reads a processor credential | no credential op exists on coord; the broker never leaves the daemon |
| a foreign local user connects to `coord.sock` | UID mismatch, refused before the request is read |
| `AKSON_COORD_UID` is unset but a driver exists | the socket was never created; there is nothing to connect to |
| the operator wants to inspect the surface | admin dominates coord, so `akson` diagnostics work without a second identity |
| …dispatches the consented digest but swaps the payload bytes | the receiver recomputes SHA-256 over what it actually read and the §4 derivation over the envelope's own members; neither matches ⇒ `422`, nothing admitted (§5) |
| …aims a consented disclosure at a different peer | the sender's TLS handshake is pinned to the recipient's certificate, so an impostor never receives the bytes; and a peer that *is* pinned refuses an envelope whose `recipient_root` is not its own (§5) |
| the daemon crashes between the commit and the send | the row is `pending` by schema default: consent spent, record present, nothing claimed to have left. A retry under the same `execution_key` resumes carriage and spends nothing; a different key stays `409 consent-spent` (§6) |
| …dispatches a staging with no reachable recipient | refused `409 unroutable-recipient` **before** the spend, so the receipt stays live (§6) |
| …stages a `task_type` the envelope schema refuses | it never stages: `stage` admits exactly what the §5 envelope admits, by asking that schema, so no receipt can ever be minted against bytes that cannot be sent (§6) |
| …retries a dispatch whose acknowledgement was lost | the body is byte-identical, so the recipient's §9.2 idempotency replays its stored acknowledgement instead of refusing `409 conflict`; the sender reaches `sent` and nothing is admitted twice (§6) |
| the operator is asked to consent to a staging that already went out | `409 already-dispatched`: the ledger, not the receipt table, decides whether this staging has disclosed anything, and the risk card's claim about it is read from the same row (§6) |
| the pinned recipient accepts the connection and then says nothing | every stage of the POST is bounded, so the attempt ends; the row is `failed` (never `sent` — nothing acknowledged) and retryable, with the stage named in `egress.detail`. The socket serves other connections meanwhile, so a remote peer cannot deny the local surface (§6) |
| …re-sends a dispatch this endpoint refused, over and over | the refusal carries a §9.2 idempotency record, so the re-send replays the same `422` and appends no second event: a peer pays one distinct request per durable row, exactly as an admitted dispatch does (§5) |
| an admitted disclosure tries to become work at the recipient | it cannot: no Task, no contract head, no work order, nothing in the approval inbox — arrival is not execution (§5) |

## Consequences

- `spec/control-protocol.md` gains a third surface and its op table; the
  document's "who may connect" section stops being "same UID" universally and
  becomes per-socket.
- `Surface` grows a third variant, so `satisfies` is no longer a two-case
  match — the dominance relation is stated explicitly rather than implied.
- Golden vectors cover each coord op's request/reply and every refusal shape,
  re-derived by `xcheck/`.
- The four open questions in the design note narrow to three: this ADR settles
  admission (question 1). Consent-receipt shape, coordination-event durability,
  and the `RestoreLineage` re-staging hint remain open and are decided as the
  ops that need them land.
- **`dispatch` consumes, commits, and now transmits.** The one-shot property is
  real and durable: the receipt's `uses 0 → 1` compare-and-set, the dispatch row
  that records it, the stage's advance to `dispatched`, and the `dispatched`
  event all commit in one transaction, and the dispatch ledger holds the receipt
  under a `UNIQUE` constraint so a second dispatch cannot commit even if that CAS
  were wrong. §5 above decides the carrier slice 2 left open, and §6 the egress
  state it needs. `coord_whoami`'s `partial` list is now empty (the field stays —
  a driver parses it), `egress.state` reports the durable column, and
  `task_status.verification` says `acknowledged`/`unacknowledged` with the
  contract-shaped fields permanently null.

  *Kept because it is the reasoning §5 rests on:* slice 2 shipped
  `egress.state: "not_implemented"` and a null `verification` rather than a
  `501`, because a `501` would have implied nothing happened when in fact the
  consent was spent — and the driver had to know that. The carrier was left open
  precisely because akson's closed contract schema cannot carry a coordination
  payload without terms the operator never read; §5 resolves that by not using
  the contract schema at all.
- **What is still open, named rather than implied.** (a) The receiving side
  verifies and acknowledges but does **not retain** an inbound coordination
  payload: §2's registry has no op to read one back, and storage without a reader
  is an unbounded liability, so the inbound half waits for the decision that
  gives it a shape. (b) The envelope is channel-authenticated, not signed, so a
  coordination dispatch is not non-repudiable (§5). (c) `stage` is unchanged, so
  an unrouted staging is still accepted and consentable — it simply cannot be
  dispatched, and that is caught before the spend (§6).
- A second driver identity would need a second UID; if that becomes common,
  revisit — but do it deliberately, not by widening this one to a group.
